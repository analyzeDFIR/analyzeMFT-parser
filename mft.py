## -*- coding: UTF-8 -*-
## mft.py
##
## Copyright (c) 2018 analyzeDFIR
## 
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.

import logging
Logger = logging.getLogger(__name__)
from os import path
from io import BytesIO
import hashlib
from construct.lib import Container

try:
    from lib.parsers import ByteParser, FileParser
    from lib.parsers.utils import StructureProperty, WindowsTime
    from structures import mft as mftstructs
except ImportError:
    from .lib.parsers import ByteParser, FileParser
    from .lib.parsers.utils import StructureProperty, WindowsTime
    from .structures import mft as mftstructs

class MFTEntryAttribute(ByteParser):
    '''
    Class for parsing Windows MFT file entry attributes
    '''
    header = StructureProperty(0, 'header')
    body = StructureProperty(1, 'body', deps=['header'])

    def _postamble(self):
        '''
        @ByteParser._postamble
        '''
        pass
    def _parse_logged_utility_stream(self):
        '''
        Args:
            N/A
        Returns:
            None
        Preconditions:
            N/A
        '''
        return None
    def _parse_bitmap(self):
        '''
        Args:
            N/A
        Returns:
            None
        Preconditions:
            N/A
        '''
        return None
    def _parse_index_root(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry index root attribute (see: structures.index)
        Preconditions:
            N/A
        '''
        index_root = Container()
        index_root.root_header = mftstructs.MFTIndexRootHeader.parse_stream(self.stream)
        node_header_position = self.stream.tell()
        index_root.node_header = mftstructs.MFTIndexNodeHeader.parse_stream(self.stream)
        index_root.entries = list()
        self.stream.seek(node_header_position + index_root.node_header.IndexValuesOffset)
        index_entry_start_position = self.stream.tell()
        index_entry_size = index_root.node_header.IndexNodeSize - mftstructs.MFTIndexNodeHeader.sizeof()
        while (self.stream.tell() - index_entry_start_position) < index_entry_size:
            try:
                index_entry_position = self.stream.tell()
                index_entry = mftstructs.MFTIndexEntry.parse_stream(self.stream)
                seek_length = mftstructs.MFTIndexEntry.sizeof() + \
                    index_entry.IndexValueSize + \
                    index_entry.IndexKeyDataSize
                if index_entry.Flags.HAS_SUB_NODE:
                    seek_length += 8
                index_root.entries.append(index_entry)
                if index_entry.Flags.IS_LAST:
                    break
                else:
                    self.stream.seek(index_entry_position + seek_length)
            except:
                break
        return self._clean_value(index_root)
    def _parse_data(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry resident data attribute
        Preconditions:
            N/A
        '''
        data = Container(content=self.stream.read(self.header.RecordLength))
        data.sha2hash = hashlib.sha256(data.content).hexdigest()
        return data
    def _parse_volume_information(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry volume information attribute (see: structures.volume_information)
        Preconditions:
            N/A
        '''
        return self._clean_value(mftstructs.MFTVolumeInformation.parse_stream(self.stream))
    def _parse_volume_name(self):
        '''
        Args:
            N/A
        Returns:
            String
            MFT entry volume name attribute (see: structures.volume_name)
        Preconditions:
            N/A
        '''
        return self.stream.read(self.header.Form.ValueLength).decode('UTF16')
    def _parse_access_control_list(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Container<String, Any>>
            MFT entry access control list attribute (see: structures.general.access_control_list)
        Preconditions:
            N/A
        '''
        try:
            acl = Container()
            acl.header = mftstructs.NTFSACLHeader.parse_stream(self.stream)
            acl_position = self.stream.tell()
            acl_size = acl.header.AclSize - mftstructs.NTFSACLHeader.sizeof()
            acl.body = list()
            while (self.stream.tell() - acl_position) < acl_size:
                ace_position = self.stream.tell()
                try:
                    ace = Container()
                    ace.header = mftstructs.NTFSACEHeader.parse_stream(self.stream)
                    ace.body = mftstructs.NTFSACEAcessMask.parse_stream(self.stream)
                    acl.body.append(ace)
                    self.stream.seek(ace_position + ace.header.AceSize)
                except:
                    break
            return self._clean_value(acl)
        except:
            return None
    def _parse_security_descriptor(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry security descriptor attribute (see: structures.security_descriptor)
        Preconditions:
            N/A
        '''
        header_position = self.stream.tell()
        security_descriptor = Container(
            header=None,
            body=Container()
        )
        security_descriptor.header = mftstructs.MFTSecurityDescriptorHeader.parse_stream(self.stream)
        if security_descriptor.header.Control.SE_SELF_RELATIVE:
            self.stream.seek(header_position + security_descriptor.header.OwnerSIDOffset)
            security_descriptor.body.OwnerSID = mftstructs.NTFSSID.parse_stream(self.stream)
            self.stream.seek(header_position + security_descriptor.header.GroupSIDOffset)
            security_descriptor.body.GroupSID = mftstructs.NTFSSID.parse_stream(self.stream)
            if security_descriptor.header.Control.SE_SACL_PRESENT:
                self.stream.seek(header_position + security_descriptor.header.SACLOffset)
                security_descriptor.body.SACL = self._parse_access_control_list()
            else:
                security_descriptor.body.SACL = None
            if security_descriptor.header.Control.SE_DACL_PRESENT:
                self.stream.seek(header_position + security_descriptor.header.DACLOffset)
                security_descriptor.body.DACL = self._parse_access_control_list()
            else:
                security_descriptor.body.DACL = None
        else:
            security_descriptor.body.OwnerSID = None
            security_descriptor.body.GroupSID = None
            security_descriptor.body.SACL = None
            security_descriptor.body.DACL = None
        return self._clean_value(security_descriptor)
    def _parse_object_id(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry object id attribute (see: structures.object_id)
        Preconditions:
            N/A
        '''
        return self._clean_value(mftstructs.MFTObjectID.parse_stream(self.stream))
    def _parse_file_name(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry file name attribute (see: structures.file_name)
        Preconditions:
            N/A
        '''
        file_name = mftstructs.MFTFileNameAttribute.parse_stream(self.stream)
        for field in file_name:
            if field.startswith('Raw') and field.endswith('Time'):
                file_name[field.replace('Raw', '')] = WindowsTime(file_name[field]).parse()
        file_name.FileName = self.stream.read(file_name.FileNameLength * 2).decode('UTF16')
        return self._clean_value(file_name)
    def _parse_attribute_list(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry attribute list attribute (see: structures.attribute_list)
        Preconditions:
            N/A
        '''
        attributes = Container()
        while self.stream.tell() < self.header.Form.ValueLength:
            AL_original_position = self.stream.tell()
            try:
                attribute_list_entry = mftstructs.MFTAttributeListEntry.parse_stream(self.stream)
                if attribute_list_entry.AttributeTypeCode == 'END_OF_ATTRIBUTES':
                    break
                self.stream.seek(AL_original_position + attribute_list_entry.AttributeNameOffset)
                attribute_list_entry.AttributeName = self.stream.read(attribute_list_entry.AttributeNameLength * 2).decode('UTF16')
            except:
                break
            else:
                if attribute_list_entry.AttributeTypeCode.lower() not in attributes:
                    attributes[attribute_list_entry.AttributeTypeCode.lower()] = list()
                attributes[attribute_list_entry.AttributeTypeCode.lower()].append(attribute_list_entry)
                self.stream.seek(AL_original_position + attribute_list_entry.RecordLength)
        return self._clean_value(attributes)
    def _parse_standard_information(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry standard information attribute (see: structures.standard_information)
        Preconditions:
            N/A
        '''
        standard_information = mftstructs.MFTStandardInformationAttribute.parse_stream(self.stream)
        for field in standard_information:
            if field.startswith('Raw') and field.endswith('Time'):
                standard_information[field.replace('Raw', '')] = WindowsTime(standard_information[field]).parse()
        return self._clean_value(standard_information)
    def _parse_body(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry attribute information
        Preconditions:
            N/A
        '''
        original_position = self.stream.tell()
        try:
            if self.header.FormCode != 0:
                return None
            parser = '_parse_%s'%self.header.TypeCode.lower()
            if not (hasattr(self, parser) and callable(getattr(self, parser))):
                return None
            self.stream.seek(original_position + self.header.Form.ValueOffset)
            return self._clean_value(getattr(self, parser)())
        finally:
            self.stream.seek(original_position + self.header.RecordLength)
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry attribute header information (see: structures.headers)
        Preconditions:
            N/A
        '''
        original_position = self.stream.tell()
        try:
            header = mftstructs.MFTAttributeHeader.parse_stream(self.stream)
            if header.NameLength > 0:
                try:
                    self.stream.seek(original_position + header.NameOffset)
                    header.Name = self.stream.read(header.NameLength * 2).decode('UTF16')
                except Exception as e:
                    Logger.error('Failed to get name of attribute from header (%s)'%str(e))
                    header.Name = None
            else:
                header.Name = None
            return self._clean_value(header)
        finally:
            self.stream.seek(original_position)

class MFTEntry(ByteParser):
    '''
    Class for parsing Windows MFT file entries
    '''
    header = StructureProperty(0, 'header')
    attributes = StructureProperty(1, 'attributes', deps=['header'])

    def _parse_attributes(self):
        '''
        Args:
            N/A
        Returns:
            List<MFTEntryAttribute>
            Attributes in MFT entry
        Preconditions:
            N/A
        '''
        attributes = list()
        self.stream.seek(self.header.FirstAttributeOffset)
        while self.stream.tell() < self.header.UsedSize:
            original_position = self.stream.tell()
            type_code = mftstructs.MFTAttributeTypeCode.parse_stream(self.stream)
            if type_code is None or type_code == 'END_OF_ATTRIBUTES':
                break
            self.stream.seek(original_position)
            attribute = MFTEntryAttribute(self.stream.getvalue()[original_position:])
            attribute.parse()
            if attribute.header is None:
                continue
            attributes.append(attribute)
            self.stream.seek(original_position + attribute.header.RecordLength)
        return self._clean_value(attributes)
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            MFT entry attribute header information (see: structures.headers)
        Preconditions:
            N/A
        '''
        header = mftstructs.MFTEntryHeader.parse_stream(self.stream)
        if header.MultiSectorHeader.RawSignature == 0x454c4946:
            header.MultiSectorHeader.Signature = 'FILE'
        elif header.MultiSectorHeader.RawSignature == 0x44414142:
            header.MultiSectorHeader.Signature = 'BAAD'
        else:
            header.MultiSectorHeader.Signature = 'CRPT'
        return self._clean_value(header)

class MFT(FileParser):
    '''
    Class for parsing Windows MFT file
    '''
    records = StructureProperty(0, 'records', dynamic=True)

    def _parse_records(self):
        '''
        Args:
            N/A
        Returns:
            Gen<MFTEntry>
            Generator of MFT entries
        Preconditions:
            N/A
        '''
        record = self.stream.read(1024)
        while record != b'':
            yield MFTEntry(record)
            record = self.stream.read(1024)
