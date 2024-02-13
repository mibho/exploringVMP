import time

import re

import hashlib

import angr, monkeyhex

import pefile

import codecs

import pydis

from iced_x86 import *

from lazy_ctypes import *

from vmp_unzipper import *

'''
--------------------------------------------------------------------------------------
'''


 
from ctypes import CFUNCTYPE, c_double

'''
--------------------------------------------------------------------------------------
'''
#proj = angr.Project("no_protections_packed_vmp1.exe")

#proj.loader

VMP_FILE_BASE = 0x140000000
SIG_VM_ENTER_DECRYPT = r'8b{2}424.+4.{1}b.{1}0{9}10{6}'

SIG_VM_ENCRYPTED_ADDRESS = r'68.{8}e8.{8}'

SIG_VM_HANDLERS_STUFF    = r'(4c8d1d.{8}.+4881(c6010{6}|ee010{6}))'
pe = pefile.PE('C:\\Users\\mibho\\Desktop\\vmp_notes\\maybe_post\\no_protections_packed_vmp1.exe')

entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint

ep_addr = entry + pe.OPTIONAL_HEADER.ImageBase

data = pe.get_memory_mapped_image()
 
 
test = vmp_unzipper()

test.load_file('C:\\Users\\mibho\\Desktop\\vmp_notes\\maybe_post\\no_protections_packed_vmp2.exe')

test.get_file_data()

test.get_vm_ep_data()
test.get_bytecode_addresses()

test.get_decryption_routine()

test.interpret_lines()

test.manual_search_for_handlers()

test.get_handler_code() 