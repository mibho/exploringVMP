import re

import hashlib

import angr, monkeyhex

import pefile

import codecs

import pydis

from iced_x86 import *

from lazy_ctypes import *
from cleanVT.dcr import dead_code_remover
from cleanVT.fx64_ef_parser import efParserClass, disasm_parsed
from cleanVT.fx64_patterns import REGEXPATTERNS
from cleanVT.fx64_operands import *

import enum

class VMP_CFO_TYPE:
    
    PUSH_RET = 5
    JMP_PTR  = 6
    JMP_REG  = 7


class offset_info:
    def __init__(self):
        self.relative_to_hex = None
        self.relative_to_byte = None
    

        # <--- "normal" method reads data by bytes. 
                            #       reading as hex for above LITERALLY reads each character. ie, len(byte) = 2
                            #       so matches using regex need to readjust .

class VM_DATA:
    ENTRY_ADDRESS_START = 0
    ENTRY_ADDRESS_END   = 1
    HANDLERS_TABLE_LOCATION   = 2

class CONSTS:
    YES_HEX = True
    NO_HEX = False

    OPERATOR_SUB = 0
    OPERATOR_ADD = 1


class vmp_unzipper:

    DEFAULT_IMAGEBASE    = 0x40000000
    VMP_IMAGEBASE_OFFSET = 0x100000000

    HEX_BYTE_LEN = 2

    VMP_FILE_BASE = 0x140000000

    SIG_VIP_FORWARD = r'(4881c601000000)'#.+(4.{1}f{2}24.{2})|(4.{1}f{2}34.{2})'

    SIG_VIP_BACKWARD = r'(4881ee01000000)'

    SIG_PUSH_RET = r'(.?4.{1}f{2}34.{2}c3c3)'

    SIG_JMP_PTR = r'(4.{1}ff24d3)'#r'(.?4.{1}f{2}24.{2})'

    SIG_VM_ENTER_DECRYPT = r'8b{2}424.+4.{1}b.{1}0{9}10{6}' # find instructions relevant to calculating bytecode addrs

    SIG_VM_ENCRYPTED_ADDRESS = r'(68.{8}e8.{8})'              # find bytecode addresses 

    bSIG_VM_ENCRYPTED_ADDRESS = b'(68.{8}e8.{8})'

    SIG_VM_HANDLERS_STUFF    = r'(4c8d1d.{8})'#.{0,128}4881((c6010{6})|(ee010{6})))'

    PATTERN_BIT_OPS = r'add|inc|dec|sub|xor|or|not|neg|and|shl|shr|rol|ror|bswap'

    def __init__(self):

        # read forward or backwards? Forward [add rsi] = READ then advance vip.     Backward [sub rsi] = advance VIP then READ
        self.read_direction = 0
        
        self.general_info = {} 

        self.first_encrypted_addr = 0
        
        self.vm_entry_decryption_steps_list = []    # instructions to calculate next bytecode address

        self.vm_encrypted_address_dict = {}     # encrypted addresses that correspond to bytecode location when decrypted

    
        self.vm_encrypted_address_positions_dict = {}   # input: address    output: pair containing indices where found.
        
        
        self.vm_encrypted_address_order_list = []

        self.vm_handlers_addresses = []

        self.vm_handler_index = {}

        self.vm_handler_code = {} # input: addr of handler output = list of instructions
        
        self.vm_type = 0            # push ret? jmp qword ptr? jmp reg? 

        self.current_file = None

        self.file_data = b''
        
        self.setup_general_info()

        self.every_disasm_parsed_dict = {}
        self.the_parser = efParserClass()
        self.filtered_handlers = {}
        self.the_cleaner = dead_code_remover()
        self.bytecode_addresses = {}

    def setup_general_info(self):

        self.general_info[VM_DATA.ENTRY_ADDRESS_START] = offset_info()
        self.general_info[VM_DATA.ENTRY_ADDRESS_END]   = offset_info()
        self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION]   = offset_info()

   

    def load_file(self, path_to_exe):

        if self.current_file is None:
            try:
                self.current_file = pefile.PE(path_to_exe)
            except Exception as err:
                print(f"Failed to load file?\n\nProvided input: {path_to_exe}\nException: {err}\n")
        else:
            print(f"a file is already loaded or something wrong :((\n")


    def get_file_data(self):
        if self.current_file is not None:
            try:
                self.file_data = self.current_file.get_memory_mapped_image()
            except Exception as err:
                print(f"Failed to get data.\n\nException: {err}\n")
    
    def testoutput(self, filename):
        try:
            with open(filename, "w") as f:
                for address in self.filtered_handlers:
                    f.write(f"Address (hex) of handler start:  {hex(address)}\n")
                    f.write(f"----------------------START------------------------\n")
                    for lines in self.filtered_handlers[address]:
                        f.write(f"\t{hex(lines[0])}: {lines[1]}\n")
                    
                    f.write(f"-----------------------END--------------------------\n")

                
        except Exception as err:
            print(f"oops? something went wrong - Exception: {err}\n")
    
    def get_vm_ep_data(self):

        ep_info = offset_info()
        ep_info.relative_to_byte = self.current_file.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_info.relative_to_hex = (ep_info.relative_to_byte << 1)


        match = re.finditer(self.SIG_VM_ENCRYPTED_ADDRESS, self.file_data.hex()[ep_info.relative_to_hex: ep_info.relative_to_hex + 512])
        
        if match:
            print(f"locations found!")
            
            for data in match:
                position = data.span()  # get start, end index where sig matched

                regex_index = position[0] % 2   # re counting each char so a hex byte considered to have len 2


                decoder = Decoder(64, bytes.fromhex(data.group(0)), DecoderOptions.NO_INVALID_CHECK)

                for instr in decoder:
                    if instr.code != Code.INVALID and regex_index != 1:
 
                        if self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_hex == None:
 
                            if instr.mnemonic == Mnemonic.CALL:
                                if position[0] == 0:

                                    relative_cip_offset = lc_u32.make_int(instr.near_branch64, CONSTS.NO_HEX)
                                    
                                    self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_byte = ep_info.relative_to_byte + relative_cip_offset
                                    self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_hex = ep_info.relative_to_hex + relative_cip_offset

                                    print(hex(self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_byte))
                                    print(hex(self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_hex))


                        if instr.op0_kind == OpKind.IMMEDIATE32TO64:
                            encrypted_addr = lc_u32.make_int(instr.immediate32to64)

                            if encrypted_addr not in self.vm_encrypted_address_positions_dict:
                                self.vm_encrypted_address_positions_dict[encrypted_addr] = offset_info()
                                self.vm_encrypted_address_positions_dict[encrypted_addr].relative_to_hex = ep_info.relative_to_hex
                                self.vm_encrypted_address_positions_dict[encrypted_addr].relative_to_byte = ep_info.relative_to_byte
                                
                            if position[0] == 0:
                                self.first_encrypted_addr = encrypted_addr
                                
                    else:
                        break
        else:
            print(f"nothing found. check if this is a VMP (TRIAL VERSION) 3.x packed file?")

    def get_bytecode_addresses(self):
        encrypted_addr = 0
        match = re.finditer(self.SIG_VM_ENCRYPTED_ADDRESS, self.file_data.hex()) 
        ep_first_encrypted = (self.current_file.OPTIONAL_HEADER.AddressOfEntryPoint << 1)   # adjusting...
        print(f"LOC OF EP_FIRST_eNCRYPTED {ep_first_encrypted}\n")

        if match:
            print(f"locations found!")
            
            for data in match:

                position = data.span()  # get start, end index where sig matched
                regex_loc = position[0] % 2
                hex_loc = (position[0] >> 1) 
                
                decoder = Decoder(64, bytes.fromhex(data.group(0)), DecoderOptions.NO_INVALID_CHECK)
                for instr in decoder:
                    if instr.code != Code.INVALID and regex_loc != 1:

                         

                        if instr.op0_kind == OpKind.IMMEDIATE32TO64:
                            encrypted_addr = lc_u32.make_int(instr.immediate32to64)
                            self.vm_encrypted_address_positions_dict[encrypted_addr] = offset_info()
                            self.vm_encrypted_address_positions_dict[encrypted_addr].relative_to_hex = hex_loc
                            self.vm_encrypted_address_positions_dict[encrypted_addr].relative_to_byte = regex_loc
                            if position[0] == ep_first_encrypted:
                                self.first_encrypted_addr = encrypted_addr
                                print(self.first_encrypted_addr)
                        elif instr.op0_kind == OpKind.NEAR_BRANCH64:
                                op = -1
                                print(f"{hex(hex_loc << 1)} {hex(hex_loc)} {hex(instr.near_branch64)}")
                                if lc_u32.is_neg_as_signed(instr.near_branch64):
                                    op = CONSTS.OPERATOR_SUB
                                else:
                                    op = CONSTS.OPERATOR_ADD
                                
                                if op == CONSTS.OPERATOR_SUB:
                                    calculated_vm_enter_from_offset = lc_u32.sub(hex_loc, instr.near_branch64)
                                elif op == CONSTS.OPERATOR_ADD:
                                    calculated_vm_enter_from_offset = lc_u32.add(hex_loc, instr.near_branch64)
                                else:
                                    print("oops")

                                difference = lc_u32.sub(self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_byte, calculated_vm_enter_from_offset)
                                if lc_u32.make_int(difference, CONSTS.NO_HEX) != 0:
                                    print(f"{encrypted_addr} not valid. removing..")
                                    if encrypted_addr in self.vm_encrypted_address_positions_dict:
                                        del self.vm_encrypted_address_positions_dict[encrypted_addr]
                                    
                                     

                        
                        #print(preserved_imm)
                    else:
                        break
        else:
            print(f"nothing found. check if this is a VMP 3.x packed file?")

    
    
    

    def get_rd_and_handlers_addr(self):
        match = re.search(self.SIG_VM_HANDLERS_STUFF, self.file_data.hex())#[self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_hex: self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_hex + 1024])

        if match:
            pos = match.span()
            hex_loc = pos[0] >> 1
            print(match.group(0))#bytes.fromhex(match2.group(0))
            decoder = Decoder(64, bytes.fromhex(match.group(0)), DecoderOptions.NO_INVALID_CHECK)
            for line in decoder:
                if line.mnemonic == Mnemonic.LEA and line.op_count == 2:
                    if line.op1_kind == OpKind.MEMORY:
                        offset = line.memory_displacement
                        print(f"found at: {hex(hex_loc)} {lc_u32.make_int(offset, False)} {hex(offset)}")
                        print(f"UHH {lc_u32.is_neg_as_signed(offset)}") #fix sig broken

                        if lc_u32.is_neg_as_signed(offset):
                            h_offset = lc_u32.get_as_signed(offset)
                        else:
                            h_offset = lc_u32.make_int(offset)

                        handler_loc = lc_u32.add(hex_loc, h_offset)
                        print(f"LOCATED: {handler_loc} {hex(handler_loc)}\n")
                        self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_byte = handler_loc
                        self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_hex = lc_u32.shl(handler_loc, 1)
                        print(hex(self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_byte))
                        print( hex(self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_hex))


        else:
            print(f"nothing found. check if this is a VMP 3.x packed file?\nor maybe handler sig size too large?")
    
    


            
    def get_handlers_locations(self):
        hex_offset = self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_hex 
        byte_read = ""
        merged_bytes = []
        address = ""
        for char in self.file_data.hex()[hex_offset: hex_offset + 4096 + 8]:    # table len is 0x800 or 2048 bytes [4096 chars]
            byte_read += char
            if len(merged_bytes) == 8:
                
                while len(merged_bytes) > 0:
                    address += merged_bytes.pop(-1)     # convert endianness of array of bytes for "real" val
                self.vm_handlers_addresses.append(lc_u32.make_int(address))
                address = ""    #reset
                

            if len(byte_read) == 2:
                merged_bytes.append(byte_read)
                byte_read = ""  # reset

            

    def adjust_handlers_value_by(self, address_read):
        
        check_for_default = lc_u32.and_b(address_read, 0xF0000000)
        print(hex(check_for_default))
        
         

        return check_for_default

    
    def setup_handlers_table(self, location):

        adjust_val = -1

        self.get_handlers_locations()
        check_addr = self.vm_handlers_addresses[0]
        adjust_val = lc_u32.make_int(self.adjust_handlers_value_by(check_addr))
        print(self.vm_handlers_addresses[0])
        print(f"entrypoint: {hex(self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_byte)}")
        


        position = 0
        count = 2048
        while count > 0:
            if location not in self.vm_handler_index:

                handler_address = lc_u32.sub(self.vm_handlers_addresses[position],  adjust_val)
                print(f"handler addr: {hex(handler_address)}")
                self.vm_handler_index[location] = handler_address
            position += 1
            location += 8
            count -= 8
        

    
    def manual_search_for_handlers(self):
        target_found = False
        terminate = False
        new_location = False

        ep_location = self.general_info[VM_DATA.ENTRY_ADDRESS_START].relative_to_byte
        print(f"{hex(ep_location)}")
        decoder = Decoder(64, self.file_data[ep_location: ep_location + 256], DecoderOptions.NO_INVALID_CHECK, ip= ep_location)
        for line in decoder:
            if line.code != Code.INVALID:
                print(f"{hex(line.ip)} - instr: {line}")
                

                if line.mnemonic == Mnemonic.JMP and line.op0_kind == OpKind.NEAR_BRANCH64:
                    print(f"distance: {hex(line.near_branch64 - line.ip)}- instr: {line}")
                    print(f"following jmp: {hex(line.near_branch64)}")
                    next_section = line.near_branch64
                    temp_ip = line.near_branch64
                    

                    while not (target_found and terminate):
                        
                        decoder = Decoder(64, self.file_data[next_section: next_section + 256], DecoderOptions.NO_INVALID_CHECK, ip= temp_ip)
                        for instr in decoder:
                            if new_location:
                                new_location = False
                                break
                            if instr.code != Code.INVALID:
                                print(f"RIP: {hex(instr.ip)}- instr: {instr}")

                                if instr.mnemonic == Mnemonic.LEA and instr.op_count == 2:
                                    if instr.op1_kind == OpKind.MEMORY and instr.memory_base == Register.RIP: 
                                        self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_byte = instr.memory_displacement
                                        self.general_info[VM_DATA.HANDLERS_TABLE_LOCATION].relative_to_hex  = instr.memory_displacement << 1
                                        print(f"maybe found? @ {hex(instr.ip)} instr = {instr}")
                                        print(f"len of table: {len(self.vm_handler_index)}")
                                        print(hex(instr.memory_displacement))
                                        self.setup_handlers_table(instr.memory_displacement)
                                        print(f"len of table: {len(self.vm_handler_index)}")
                                        print("ok done")
                                        target_found = True
                                        return
                                if instr.mnemonic == Mnemonic.JMP and instr.op0_kind == OpKind.NEAR_BRANCH64:
                                    print({type(instr.memory_base)})
                                    distance = instr.near_branch64 - instr.ip
                                    signed_distance = lc_u32.get_as_signed(distance)
                                    

                                    if signed_distance < 0: # negative
                                        next_section = instr.ip + signed_distance
                                    else:
                                        next_section = instr.ip + distance
                                    
                                    temp_ip = next_section
                                    new_location = True
                                    print(f"jmp target found: {hex(instr.ip + signed_distance)}")
                                    print(f"distance: {hex(instr.near_branch64 - instr.ip)}- instr: {instr}")
                                    print(f"following jmp: {hex(instr.near_branch64)}")
                                    
    def get_handler_code(self):
        formatter = Formatter(FormatterSyntax.INTEL)
        formatter.space_between_memory_add_operators = True
        formatter.hex_suffix = ""
        formatter.hex_prefix = "0x"
        target_found = False
        terminate = False
        jmp_taken = False
        in_jcc = False
        
        body = []
        jcc_list = []
        jcc_block = []
        cnt = 0
        encountered_jcc = {}

        for handler_location in self.vm_handler_index:
            cnt += 1
            section_of_handler = self.vm_handler_index[handler_location]
            if section_of_handler not in self.vm_handler_code:
                self.vm_handler_code[section_of_handler] = []
            #print(f"count: {cnt} - handler section: {hex(section_of_handler)} - handler location: {hex(handler_location)}\n")

            initial_disasm = Decoder(64, self.file_data[section_of_handler: section_of_handler + 256], DecoderOptions.NO_INVALID_CHECK, ip= section_of_handler)
            
            for line in initial_disasm:
            
                if line.code != Code.INVALID:
                    


                    line_string = formatter.format(line)
                    #print(f"line string: {line_string}")
                    if line_string not in self.every_disasm_parsed_dict:
                        self.every_disasm_parsed_dict[line_string] = disasm_parsed()
                        self.the_parser.complete_parse(line_string)
                        parsed = self.the_parser.copy()
                        self.every_disasm_parsed_dict[line_string].set_operator(parsed[0])
                        self.every_disasm_parsed_dict[line_string].operand_count = (parsed[1])
                        self.every_disasm_parsed_dict[line_string].operand_list = (parsed[2])
                        self.the_parser.reset()
                    #print(f"{hex(line.ip)} - instr: {line}")
                    #print(f"cnt: {cnt} inside for loop0")

                    if line.mnemonic == Mnemonic.JMP and line.op0_kind == OpKind.NEAR_BRANCH64: # take the jmp
                        #print(f"distance: {hex(line.near_branch64 - line.ip)}- instr: {line}")
                        #print(f"following jmp: {hex(line.near_branch64)}")
                        next_section = line.near_branch64
                        current_ip = line.near_branch64

                        while (not target_found and not terminate) or (len(jcc_list) > 0 or in_jcc):

                           # print("inside while loop2")

                            if len(jcc_list) > 0 and terminate: #and not in_jcc:
                                next_section = jcc_list.pop(0)
                                current_ip = next_section
                                in_jcc = True
                        
                            inner_disasm = Decoder(64, self.file_data[next_section: next_section + 256], DecoderOptions.NO_INVALID_CHECK, ip= current_ip)

                            for instr in inner_disasm:

                                


                                #print("inside for loop of while loop1")

                                if jmp_taken:
                                    jmp_taken = False   # reset.
                                    break               # leave loop to get disasm of next section
                                
                                if instr.code != Code.INVALID:

                                    instr_string = formatter.format(instr)
                                    #print(f"instr string: {instr_string}")
                                    if instr_string not in self.every_disasm_parsed_dict:
                                        self.every_disasm_parsed_dict[instr_string] = disasm_parsed()
                                        self.the_parser.complete_parse(instr_string)
                                        parsed = self.the_parser.copy()
                                        self.every_disasm_parsed_dict[instr_string].set_operator(parsed[0])
                                        self.every_disasm_parsed_dict[instr_string].operand_count = (parsed[1])
                                        self.every_disasm_parsed_dict[instr_string].operand_list = (parsed[2])
                                        self.the_parser.reset()


                                    #print(f"RIP: {hex(instr.ip)}- instr: {instr}")
                                    #print(f"jcc_list len:{len(jcc_list)} in_jcc: {in_jcc} terminate: {terminate}")

                                    if (instr.mnemonic == Mnemonic.JMP and instr.op0_kind == OpKind.MEMORY) or instr.mnemonic == Mnemonic.RET:  # push ret, jmp qword ptr
                                        
                                        if not terminate:
                                            body.append((instr.ip, instr_string))
                                        else:
                                            if in_jcc:
                                                jcc_block.append((instr.ip, instr_string))
                                                in_jcc = False
                                        
                                        terminate = True
                                        
                                        

                                        #print("terminate")
                                        break


                                    elif instr.mnemonic == Mnemonic.JMP and instr.op0_kind == OpKind.NEAR_BRANCH64:   # valid jmp location 
                                        destination = instr.near_branch64
                                        current_location = instr.ip


                                        print({type(instr.memory_base)})
                                        distance = destination - current_location
                                        signed_val_of_distance = lc_u32.get_as_signed(distance)
                                        

                                        if signed_val_of_distance < 0: # negative
                                            next_section = current_location + signed_val_of_distance
                                        else:
                                            next_section = current_location + distance
                                        
                                        current_ip = next_section
                                        jmp_taken = True
                                        
                                    else:   # not a jmp label so include.
                                        if instr.mnemonic >= Mnemonic.JA and instr.mnemonic <= Mnemonic.JS and instr.mnemonic != Mnemonic.JMP:
                                            if instr.near_branch64 not in encountered_jcc:
                                                jcc_list.append(instr.near_branch64)
                                                encountered_jcc[instr.near_branch64] = 0
                                            

                                        if not terminate:
                                            body.append((instr.ip, instr_string))
                                        else:
                                            if in_jcc:
                                                jcc_block.append((instr.ip, instr_string))

                                if terminate and not in_jcc:
                                    break
                        
                        if len(jcc_block) > 0:
                            self.vm_handler_code[section_of_handler].append(jcc_block.copy())
                            jcc_block.clear()
                            encountered_jcc.clear()
                    else:   # not a jmp.

                        if terminate and not in_jcc:
                            break
                        body.append((line.ip, line_string))
        

            if terminate or target_found:
                terminate = False
                target_found = False
            self.vm_handler_code[section_of_handler].append(body.copy())
            body.clear()
        
        print(len(self.vm_handler_code))
        
        

            #return
    

    def grab_and_clean_all_handlers(self):
        for handler_location in self.vm_handler_code:
            
            blocks = self.vm_handler_code[handler_location]
            for block in blocks:
                loc_assigned = False
                start_addr = 0

                for code in block:
                    if not loc_assigned:
                        index = 0
                        start_addr = code[0]
                        if start_addr not in self.filtered_handlers:
                            self.filtered_handlers[start_addr] = []
                        else:
                            break
                        loc_assigned = True
                    parsed_line_data = self.every_disasm_parsed_dict[code[1]]
                    if parsed_line_data is not None:
                        current_line_operator = parsed_line_data.get_operator()
                        curr_operands = parsed_line_data.get_operands()
                        self.the_cleaner.process_lines(current_line_operator, curr_operands, index)
                    index += 1
                #print(block)
                keep_these = self.the_cleaner.return_lines_to_keep()
                #print(f"{len(keep_these)} orig len: {len(block)}")
                #if len(keep_these) == len(block):
                #    print(f"No dead code in current block.")
                fixed_list = sorted(keep_these, reverse=False)
                for num in fixed_list:
                    self.filtered_handlers[start_addr].append(block[num])
                #    print(f"keep these: {num}")
                keep_these.clear()
                self.the_cleaner.reset()
        
        
        
        c2 = 0
        for handler_location in self.vm_handler_code:
            if handler_location in self.filtered_handlers:
                c2 += 1
                
                
        


    def show_code(self):
        for addr in self.vm_handler_code:
            print(f"{hex(addr)}: {self.vm_handler_code[addr]}\n")         
        print(type(Mnemonic.JMP))         

    def get_decryption_routine(self):
        match = re.search(self.SIG_VM_ENTER_DECRYPT, self.file_data.hex())

        if match:
            

            decoder = Decoder(64, bytes.fromhex(match.group(0)), DecoderOptions.NO_INVALID_CHECK)
            for line in decoder:
                print(line) 
                if line.op_count == 1 or line.op_count == 2:
                    if line.op0_kind == OpKind.REGISTER:
                        if line.op0_register == Register.RSI or line.op0_register == Register.ESI:
                            self.vm_entry_decryption_steps_list.append(line.__str__())
        else:
            print(f"nothing found. check if this is a VMP 3.x packed file?")
        
        if len(self.vm_entry_decryption_steps_list) > 0:
            self.vm_entry_decryption_steps_list.pop(-1)
            self.vm_entry_decryption_steps_list.pop(0)
            print(self.vm_entry_decryption_steps_list)
          
        
    
    def interpret_lines(self):
        if len(self.vm_entry_decryption_steps_list) > 0:
            for addresses in self.vm_encrypted_address_positions_dict:
                decrypted = lc_u32.make_int(addresses)
                for step in self.vm_entry_decryption_steps_list:
                    constant = None

                    found = re.search(self.PATTERN_BIT_OPS, step)
                    if found:

                        op = found.group(0)
                        val = step.split(',')
                        if len(val) >= 2:
                            if val[1][-1] == 'h':
                                constant = int((val[1][:-1]),16)
                            else:
                                constant = int(val[1], 0)
                        else:
                            constant = None
                        
                        if op == 'neg':
                            decrypted = lc_u32.neg(decrypted)
                        elif op == 'bswap':
                            decrypted = lc_u32.bswap(decrypted)
                        elif op == 'not':
                            decrypted = lc_u32.not_b(decrypted)
                        
                        elif op == 'dec':
                            decrypted = lc_u32.sub(decrypted, 1)
                        elif op == 'inc':
                            decrypted = lc_u32.add(decrypted, 1)
                        

                        elif op == 'add':
                            if constant is not None:
                                decrypted = lc_u32.add(decrypted, constant)
                        elif op == 'sub':
                            if constant is not None:
                                decrypted = lc_u32.sub(decrypted, constant)
                        
                        elif op == 'xor':
                            if constant is not None:
                                decrypted = lc_u32.xor(decrypted, constant)
                        elif op == 'or':
                            if constant is not None:
                                decrypted = lc_u32.or_b(decrypted, constant)
                        elif op == 'and':
                            if constant is not None:
                                decrypted = lc_u32.and_b(decrypted, constant)
                        elif op == 'shl':
                            if constant is not None:
                                decrypted = lc_u32.shl(decrypted, constant)
                        elif op == 'shr':
                            if constant is not None:
                                decrypted = lc_u32.shr(decrypted, constant)
                        elif op == 'rol':
                            if constant is not None:
                                decrypted = lc_u32.rol_by(decrypted, constant)
                        elif op == 'ror':
                            if constant is not None:
                                decrypted = lc_u32.ror_by(decrypted, constant)
                
                print(f"initial: {addresses} decrypted: {lc_u32.make_int(decrypted)}")
                if addresses not in self.bytecode_addresses:
                    self.bytecode_addresses[addresses] = lc_u32.make_int(decrypted)
                  
