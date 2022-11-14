#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


import sys, string, base64, os, re
from threading import Thread
from platform import system as get_system_type
from Crypto.Cipher import AES
from uuid import UUID, uuid4
from ipaddress import ip_address
from copy import deepcopy
from time import sleep, time
from pyperclip import copy as copy2cb

if get_system_type() == 'Linux':
	import gnureadline as global_readline
else:
	import readline as global_readline


''' Colors '''
MAIN = '\001\033[38;5;85m\002'
GREEN = '\001\033[38;5;82m\002'
GRAY = PLOAD = '\001\033[38;5;246m\002'
NAME = '\001\033[38;5;228m\002'
RED = '\001\033[1;31m\002'
FAIL = '\001\033[1;91m\002'
ORANGE = '\033[0;38;5;214m\002'
LRED = '\033[0;38;5;202m\002'
BOLD = '\001\033[1m\002'
UNDERLINE = '\001\033[4m\002'
END = '\001\033[0m\002'


''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
WARN = f'{LRED}Warning{END}'
IMPORTANT = f'{ORANGE}Important{END}'
FAILED = f'{RED}Fail{END}'
DEBUG = f'{ORANGE}Debug{END}'


cwd = os.path.dirname(os.path.abspath(__file__))


''' Command Prompt Settings '''

class Main_prompt:
	
	original_prompt = prompt = f"{UNDERLINE}Villain{END} > "
	main_prompt_ready = True
	SPACE = '#>SPACE$<#'

	
	@staticmethod
	def rst_prompt(prompt = prompt, prefix = '\r'):
		
		Main_prompt.main_prompt_ready = True
		sys.stdout.write(prefix + Main_prompt.prompt + global_readline.get_line_buffer())


	@staticmethod
	def set_main_prompt_ready():
		Main_prompt.main_prompt_ready = True



''' General Functions '''

def exit_with_msg(msg):
	print(f"[{DEBUG}] {msg}")
	sys.exit(0)



def print_fail_and_return_to_prompt(msg):			
	print(f'\r[{FAILED}] {msg}')
	Main_prompt.rst_prompt(force_rst = True)



def print_shadow(msg):
	print(f'{GRAY}{msg}{END}')
	


def chill():
	pass



def is_valid_uuid(value):

	 try:
		  UUID(str(value))
		  return True

	 except:
		  return False



def is_valid_ip(ip_addr):
	
	try:
		ip_object = ip_address(ip_addr)
		return True
		
	except ValueError:
		return False



def print_table(rows, columns):

	columns_list = [columns]
	
	for item in rows: 
		columns_list.append([str(item[col] if item[col] is not None else '') for col in columns])
		
	col_size = [max(map(len, col)) for col in zip(*columns_list)]
	format_str = '  '.join(["{{:<{}}}".format(i) for i in col_size])
	columns_list.insert(1, ['-' * i for i in col_size])
		
	for item in columns_list:
		item[-1] = f'{GREEN}{item[-1]}{END}' if item[-1] == 'Active' else item[-1]
		item[-1] = f'{ORANGE}{item[-1]}{END}' if (item[-1] in ['Unreachable', 'Undefined']) else item[-1]
		print(format_str.format(*item))
			


def clone_dict_keys(_dict):
	
	clone = deepcopy(_dict)
	clone_keys = clone.keys()
	return clone_keys



''' Encryption '''
def encrypt_msg(aes_key, msg, iv):
	enc_s = AES.new(aes_key, AES.MODE_CFB, iv)
	
	if type(msg) == bytes:
		cipher_text = enc_s.encrypt(msg)
	else:
		cipher_text = enc_s.encrypt(msg.encode('utf-8'))
		
	encoded_cipher_text = base64.b64encode(cipher_text)
	return encoded_cipher_text



def decrypt_msg(aes_key, cipher, iv):
	
	try:
		decryption_suite = AES.new(aes_key, AES.MODE_CFB, iv)
		plain_text = decryption_suite.decrypt(base64.b64decode(cipher + b'=='))
		return plain_text if type(plain_text) == str else plain_text.decode('utf-8', 'ignore')
	
	except TypeError:
		pass
