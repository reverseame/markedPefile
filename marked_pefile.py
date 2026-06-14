import re
from .pefile.pefile import PE, two_way_dict, MAX_SYMBOL_EXPORT_COUNT, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS, Structure, SectionStructure, UNW_FLAG_CHAININFO, PEFormatError 

try:
    import volatility.debug as logging
except ImportError:
    import logging

PAGE_SIZE = 0x1000

marks_types = [
    ('UNKW_BYTE',                           0),
    ('NULL_PAGE',                           1),
    ('DOS_HEADER_BYTE',                     2),
    ('DOS_STUB_BYTE',                       3),
    ('NT_HEADERS_BYTE',                     4),
    ('FILE_HEADER_BYTE',                    5),
    ('OPTIONAL_HEADER_BYTE',                6),
    ('DATA_DIRECTORY_BYTE',                 7),
    ('SECTION_HEADER_BYTE',                 8),
    ('IMAGE_DIRECTORY_ENTRY_EXPORT',        9),
    ('IMAGE_DIRECTORY_ENTRY_IMPORT',        10),
    ('IMAGE_DIRECTORY_ENTRY_RESOURCE',      11),
    ('IMAGE_DIRECTORY_ENTRY_EXCEPTION',     12),
    ('IMAGE_DIRECTORY_ENTRY_SECURITY',      13),
    ('IMAGE_DIRECTORY_ENTRY_BASERELOC',     14),
    ('IMAGE_DIRECTORY_ENTRY_DEBUG',         15),
    # Architecture on non-x86 platforms
    ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',     16),
    ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',     17),
    ('IMAGE_DIRECTORY_ENTRY_TLS',           18),
    ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',   19),
    ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',  20),
    ('IMAGE_DIRECTORY_ENTRY_IAT',           21),
    ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',  22),
    ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',23),
    ('IMAGE_DIRECTORY_ENTRY_RESERVED',      24),
    ('END_PAGE_PADDING',                    27),
    ('THUNK_DATA',                          28),
    ('IMPORT_BY_NAME',                      29),
    ('IMPORT_MODULE_NAME',                  30),
    ('STRING_UNICODE',                      31),
    ('STRING_ASCII',                        32),
    ('TABLE',                               33),
    ('PRE_TABLE',                           34),
    ('JUMPED_BYTE',                         35),
    ('INSTRUCTION_BYTE',                    36)
    ]

MARKS = two_way_dict(marks_types)

# IMAGE_LOAD_CONFIG_DIRECTORY constants
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf0000000
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28

def all_zero(data):
    for byte in data:
        # Iterating bytes yields ints in Python 3; tolerate str too.
        if (byte if isinstance(byte, int) else ord(byte)) != 0:
            return False
    return True

def section_real_size(section):
        max_size = max(section.SizeOfRawData, section.Misc_VirtualSize)
        return max_size if not max_size % PAGE_SIZE else (max_size // PAGE_SIZE + 1) * PAGE_SIZE

class MarkedPE(PE):
    def __init__(self, name=None, data=None, fast_load=None, max_symbol_exports=MAX_SYMBOL_EXPORT_COUNT, virtual_layout=False, valid_pages=None, base_address=None, architecture=None):
        try:
            super(MarkedPE, self).__init__(name=name, data=data, fast_load=fast_load, max_symbol_exports=max_symbol_exports, virtual_layout=virtual_layout)
        except PEFormatError:
            delattr(self, 'DOS_HEADER')

        self.__size__ = len(data)
        self.__base_address__ = base_address
        self.__architecture__ = architecture

        if valid_pages:
            self.__valid_pages__ = valid_pages
            self.__visited__ = []
            for page in valid_pages:
                if page:
                    self.__visited__.extend( [MARKS['UNKW_BYTE']] * PAGE_SIZE)
                else:
                    self.__visited__.extend( [MARKS['NULL_PAGE']] * PAGE_SIZE)
        else:
            self.__visited__ = [MARKS['UNKW_BYTE']] * self.__size__
            self.valid_pages()
        if self.PE_TYPE:
            self.marking()
        else:
            dump = SectionStructure(PE.__IMAGE_SECTION_HEADER_format__, pe=self )
            dump.Name = 'dump'
            dump.Misc = 0
            dump.Misc_PhysicalAddress = 0
            dump.Misc_VirtualSize = self.__size__
            dump.PointerToRawData = 0
            dump.PointerToRawData_adj = 0
            dump.SizeOfRawData = self.__size__
            dump.VirtualAddress = 0
            dump.VirtualAddress_adj = 0
            dump.next_section_virtual_address = None
            dump.real_size = section_real_size(dump)
            self.sections.append(dump)

    def valid_pages(self):
        for page_offset in range(0, self.__size__, PAGE_SIZE):
            if all_zero(self.__data__[page_offset:page_offset+PAGE_SIZE]):
                self.set_visited(pointer=page_offset, size=PAGE_SIZE, tag=MARKS['NULL_PAGE'])

    def set_visited(self, object=None, tag=None, force=False, pointer=None, size=None):
        if object:
            pointer = object.get_file_offset()
            size = object.sizeof()
        index = pointer
        while  index < pointer+size:
            if self.__visited__[index] == MARKS['UNKW_BYTE'] or self.__visited__[index] == tag or force:
                self.__visited__[index] = tag
            elif self.__visited__[index] == MARKS['NULL_PAGE']:
                # ToDelete: Duplication error
                pass

            else:
                #raise PeMemError(self.__visited__[index], 'Visiting space previously visited', pointer)
                logging.warning('Visiting space (Module address:{} Offset:{}) as {} previously visited as {}'.format(self.__base_address__, index, MARKS[tag], MARKS[self.__visited__[index]]))
            index += 1

    def visit_unwind(self, UnwindInfoStruct):
        unwind_init_size = Structure(self.__UNWIND_INFO_format_1__).sizeof()
        code_size = Structure(self.__UNWIND_CODE_format__).sizeof()
        untime_function_size = Structure(self.__IMAGE_RUNTIME_FUNCTION_ENTRY_format__).sizeof()
        self.set_visited(pointer=UnwindInfoStruct.get_file_offset(),
        size=unwind_init_size + ((UnwindInfoStruct.CountOfUnwindCode + 1) & ~1) * code_size,  tag=MARKS['IMAGE_DIRECTORY_ENTRY_EXCEPTION'])

        if UnwindInfoStruct.Flags & UNW_FLAG_CHAININFO:
            self.set_visited(pointer=UnwindInfoStruct.get_file_offset() + unwind_init_size + ((UnwindInfoStruct.CountOfUnwindCode + 1) & ~1) * code_size, size=untime_function_size)
            if UnwindInfoStruct.chained_unwind_info.UnwindInformation:
                self.visit_unwind(UnwindInfoStruct.chained_unwind_info.UnwindInfoStruct)

    def set_zero_word(self, address):
        self.__data__ = self.__data__[:address + 2] + b'\x00\x00' + self.__data__[address + 4:]

    def set_zero_double_word(self, address):
        self.__data__ = self.__data__[:address + 2] + b'\x00\x00\x00\x00\x00\x00' + self.__data__[address + 8:]

    def get_section_by_name(self, section_name):
        for section in self.sections:
            name = section.Name
            if isinstance(name, (bytes, bytearray)):
                name = bytes(name).decode('latin-1', 'replace')
            if re.match(section_name, name):
            #if section.Name == section_name:
                return section
        return None

    def marking_exception_directory(self, exception_directory):
        for runtime_function in exception_directory:
                self.set_visited(runtime_function, tag=MARKS['IMAGE_DIRECTORY_ENTRY_EXCEPTION'])
                try:
                    if runtime_function.UnwindInformation & 1:
                        self.marking_exception_directory(runtime_function.RuntimeFunctionStruct)
                    elif runtime_function.UnwindInformation:
                        self.visit_unwind(runtime_function.UnwindInfoStruct)
                except:
                    # TODO log some warning here
                    pass

    def marking(self):
        address_size = 4 if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE else 8
        null_address = b'\x00' * address_size

        self.set_visited(self.DOS_HEADER, MARKS['DOS_HEADER_BYTE'])
        self.set_visited(self.DOS_STUB, MARKS['DOS_STUB_BYTE'])
        self.set_visited(self.NT_HEADERS, MARKS['NT_HEADERS_BYTE'])
        self.set_visited(self.FILE_HEADER, MARKS['FILE_HEADER_BYTE'])
        self.set_visited(self.OPTIONAL_HEADER, MARKS['OPTIONAL_HEADER_BYTE'])

        for directory in self.OPTIONAL_HEADER.DATA_DIRECTORY:
            self.set_visited(directory, MARKS['DATA_DIRECTORY_BYTE'])
            if directory.VirtualAddress and directory.Size:
                if directory.VirtualAddress < directory.VirtualAddress + directory.Size < self.__size__ :
                    if directory.name=='IMAGE_DIRECTORY_ENTRY_SECURITY':
                        pass
                        # TODO: check self.set_visited(pointer=directory.VirtualAddress+directory.get_file_offset(), size=directory.Size, tag=MARKS[directory.name]) 
                    elif directory.name=='IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG':
                        self.set_visited(pointer=directory.VirtualAddress, size=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size,
                                tag=MARKS[directory.name])
                    elif directory.name=='IMAGE_DIRECTORY_ENTRY_EXCEPTION':
                        pass
                    else:
                        self.set_visited(pointer=directory.VirtualAddress, size=directory.Size,
                                tag=MARKS[directory.name])
                else:
                    self._PE__warnings.append( "Corrupt directory \"{}\" at offset {} with {} bytes, is out of input range".format(directory.name, directory.VirtualAddress, directory.Size))


        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            for import_directory in self.DIRECTORY_ENTRY_IMPORT:
                thunk_data_index = import_directory.struct.OriginalFirstThunk
                if import_directory.struct.Name:
                    self.set_visited(pointer=import_directory.struct.Name, size=len(import_directory.dll)+1, tag=MARKS['IMPORT_MODULE_NAME']) # known=True
                    index = import_directory.struct.Name + len(import_directory.dll)+1
                    while self.__data__[index]==0x90 and index<thunk_data_index:
                        self.set_visited(pointer=index, size=1, tag=MARKS['IMPORT_MODULE_NAME'])
                        index += 1

                while True:
                    # For 
                    self.set_visited(pointer=thunk_data_index, size=address_size, tag=MARKS['THUNK_DATA']) # known=True
                    if self.__data__[thunk_data_index:thunk_data_index+address_size]==null_address:
                        break
                    thunk_data_index += address_size

                for function in import_directory.imports:
                    if hasattr(function, 'hint_name_table_rva') and function.hint_name_table_rva:
                        self.set_visited(pointer=function.hint_name_table_rva, size=len(function.name)+3, tag=MARKS['IMPORT_BY_NAME']) # known=True

                        if (((function.hint_name_table_rva + len(function.name)+3) % 2) != 0) and (self.__data__[function.hint_name_table_rva + len(function.name)+3] == 0):
                            self.set_visited(pointer=function.hint_name_table_rva + len(function.name)+3, size=1, tag=MARKS['IMPORT_BY_NAME']) # known=True
                    
                    
   
        for section in self.sections:
            self.set_visited(section, MARKS['SECTION_HEADER_BYTE'])

        if hasattr(self, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                if not resource_type.struct.all_zeroes():
                    for resource_name in resource_type.directory.entries:
                        if not resource_name.struct.all_zeroes():
                            for resource_language in resource_name.directory.entries:
                                if not resource_language.struct.all_zeroes():
                                    self.set_visited(pointer=resource_language.data.struct.OffsetToData, 
                                                size=resource_language.data.struct.Size,
                                                tag=MARKS['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if hasattr(self, 'DIRECTORY_ENTRY_EXCEPTION'):
        	# XXX: To Check
            self.marking_exception_directory(self.DIRECTORY_ENTRY_EXCEPTION)

        if hasattr(self, 'DIRECTORY_ENTRY_TLS'):
            if self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
                AddressOfCallBacksIndex = self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.__base_address__
                while True:
                    self.set_visited(pointer=AddressOfCallBacksIndex, size=address_size, tag=MARKS['IMAGE_DIRECTORY_ENTRY_TLS'])
                    if self.__data__[AddressOfCallBacksIndex:AddressOfCallBacksIndex+address_size] == null_address:
                        break
                    AddressOfCallBacksIndex += address_size
        
        if hasattr(self, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            if (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>68) or \
            (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>104):
                self.set_visited(pointer=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable - self.__base_address__, 
                                        size=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount * 4,
                                        tag=MARKS['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'])

            if (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>88) or \
            (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>144):
                extra_bytes = (self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT

                self.set_visited(pointer=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable - self.__base_address__, 
                                        size=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount * (4+extra_bytes),
                                        tag=MARKS['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'])
            
            if (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>108) or \
            (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>168):
                if hasattr(self.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'GuardAddressTakenIatEntryTable'):
                    self.set_visited(pointer=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardAddressTakenIatEntryTable - self.__base_address__, 
                                        size=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardAddressTakenIatEntryCount * 4,
                                        tag=MARKS['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'])
            
            if (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>116) or \
            (self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size>184):
                if hasattr(self.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'GuardLongJumpTargetTable'):
                    self.set_visited(pointer=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardLongJumpTargetTable - self.__base_address__, 
                                            size=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardLongJumpTargetCount * 4,
                                            tag=MARKS['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'])
                        
        if hasattr(self, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for delay_import in self.DIRECTORY_ENTRY_DELAY_IMPORT:
                if delay_import.struct.szName:
                    self.set_visited(pointer=delay_import.struct.szName, 
                                size=len(delay_import.dll) + 1,
                                tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                if delay_import.struct.pINT:
                    index = delay_import.struct.pINT
                    while True:
                        self.set_visited(pointer=index,
                                    size=address_size,
                                    tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                        if self.__data__[index: index + address_size] == null_address:
                            break
                        index += address_size
                if delay_import.struct.pIAT:
                    index = delay_import.struct.pIAT
                    while True:
                        self.set_visited(pointer=index,
                                    size=address_size,
                                    tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                        if self.__data__[index: index + address_size] == null_address:
                            break
                        index += address_size
                if delay_import.struct.pBoundIAT:
                    index = delay_import.struct.pBoundIAT
                    while True:
                        self.set_visited(pointer=index,
                                    size=address_size,
                                    tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                        if self.__data__[index: index + address_size] == null_address:
                            break
                        index += address_size
                if delay_import.struct.pUnloadIAT:
                    index = delay_import.struct.pUnloadIAT
                    while True:
                        self.set_visited(pointer=index,
                                    size=address_size,
                                    tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                        if self.__data__[index: index + address_size] == null_address:
                            break
                        index += address_size
                for function_import in delay_import.imports:
                    if function_import.name != 'IMAGE_THUNK_DATA':
                        if function_import.hint_name_table_rva:
                            self.set_visited(pointer=function_import.hint_name_table_rva, 
                                        size=2,
                                        tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                        if function_import.name_offset:
                            self.set_visited(pointer=function_import.name_offset, 
                                        size=len(function_import.name)+1,
                                        tag=MARKS['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'])
                    

        end_header_data =  self.__visited__.index(0)
        end_header = self.sections[0].VirtualAddress
        if all_zero(self.__data__[end_header_data: end_header]):
            self.set_visited(pointer=end_header_data, size = end_header - end_header_data, tag=MARKS['END_PAGE_PADDING'])

        for section in self.sections:
            section.real_size = section_real_size(section)
            if (section.VirtualAddress + min(section.SizeOfRawData, section.Misc_VirtualSize) < section.VirtualAddress + section.real_size < self.__size__) and all_zero(self.__data__[section.VirtualAddress + min(section.SizeOfRawData, section.Misc_VirtualSize):section.VirtualAddress + section.real_size]):
                self.set_visited(pointer=section.VirtualAddress + min(section.SizeOfRawData, section.Misc_VirtualSize), 
                                size=section.real_size - min(section.SizeOfRawData, section.Misc_VirtualSize),
                                tag=MARKS['END_PAGE_PADDING'])

            elif (section.VirtualAddress + max(section.SizeOfRawData, section.Misc_VirtualSize) < section.VirtualAddress + section.real_size < self.__size__) and all_zero(self.__data__[section.VirtualAddress + max(section.SizeOfRawData, section.Misc_VirtualSize):section.VirtualAddress + section.real_size]):
                self.set_visited(pointer=section.VirtualAddress + max(section.SizeOfRawData, section.Misc_VirtualSize), 
                                size=section.real_size - max(section.SizeOfRawData, section.Misc_VirtualSize),
                                tag=MARKS['END_PAGE_PADDING'])
        header = SectionStructure(PE.__IMAGE_SECTION_HEADER_format__, pe=self )
        header.Name = 'header'
        header.Misc = 0
        header.Misc_PhysicalAddress = 0
        header.Misc_VirtualSize = self.sections[0].VirtualAddress
        header.PointerToRawData = 0
        header.PointerToRawData_adj = 0
        header.SizeOfRawData = self.sections[0].PointerToRawData
        header.VirtualAddress = 0
        header.VirtualAddress_adj = 0
        header.next_section_virtual_address = self.sections[0].VirtualAddress
        header.real_size = section_real_size(header)
        self.sections.append(header)

        full_pe = SectionStructure(PE.__IMAGE_SECTION_HEADER_format__, pe=self )
        full_pe.Name = 'PE'
        full_pe.Misc = 0
        full_pe.Misc_PhysicalAddress = 0
        full_pe.Misc_VirtualSize = self.__size__
        full_pe.PointerToRawData = 0
        full_pe.PointerToRawData_adj = 0
        full_pe.SizeOfRawData = self.__size__
        full_pe.VirtualAddress = 0
        full_pe.VirtualAddress_adj = 0
        full_pe.next_section_virtual_address = None
        full_pe.real_size = section_real_size(full_pe)
        self.sections.append(full_pe)

class PeMemError(Exception):
    def __init__(self, code, msg, address=None):
        self.code = code
        self.msg = msg
        self.add = address

    def __str__(self):
        return repr('Error: {}: {} - {}'.format(self.code, self.msg, self.add))

     
