#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


import sys, string, base64, os, re, traceback
import netifaces as ni
from random import randint, choice, randrange
from threading import Thread, enumerate as enumerate_threads
from subprocess import check_output
from platform import system as get_system_type
from Crypto.Cipher import AES
from uuid import UUID, uuid4
from ipaddress import ip_address
from copy import deepcopy
from time import sleep, time
from pyperclip import copy as copy2cb
from string import ascii_uppercase, ascii_lowercase, digits
from importlib import import_module

system_type = get_system_type()

# if system_type in ['Linux', 'Darwin']:
# 	import gnureadline as global_readline
# else:
import readline as global_readline


''' Colors '''
MAIN = '\001\033[38;5;85m\002'
GREEN = '\001\033[38;5;82m\002'
GRAY = PLOAD = '\001\033[38;5;246m\002'
NAME = '\001\033[38;5;228m\002'
RED = '\001\033[1;31m\002'
FAIL = '\001\033[1;91m\002'
ORANGE = '\001\033[0;38;5;214m\002'
LRED = '\001\033[0;38;5;196m\002'
BOLD = '\001\033[1m\002'
PURPLE = '\001\033[0;38;5;141m\002'
BLUE = '\001\033[0;38;5;12m\002'
UNDERLINE = '\001\033[4m\002'
UNSTABLE = '\001\033[5m\002'
END = '\001\033[0m\002'


''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
WARN = f'{ORANGE}Warning{END}'
IMPORTANT = f'{ORANGE}Important{END}'
FAILED = f'{RED}Fail{END}'
ERR = f'{LRED}Error{END}'
DEBUG = f'{ORANGE}Debug{END}'
CHAT =f'{BLUE}Chat{END}'
GRN_BUL = f'[{GREEN}*{END}]'
META = '[\001\033[38;5;93m\002M\001\033[38;5;129m\002e\001\033[38;5;165m\002t\001\033[38;5;201m\002a\001\033[0m\002]'

cwd = os.path.dirname(os.path.abspath(__file__))


''' Command Prompt Settings '''

class Main_prompt:
	
	original_prompt = prompt = f"{UNDERLINE}Villain{END} > "
	ready = True
	SPACE = '#>SPACE$<#'
	exec_active = False

	
	@staticmethod
	def rst_prompt(prompt = prompt, prefix = '\r'):
		
		Main_prompt.ready = True
		Main_prompt.exec_active = False
		sys.stdout.write(prefix + Main_prompt.prompt + global_readline.get_line_buffer())


	@staticmethod
	def set_main_prompt_ready():
		Main_prompt.exec_active = False
		Main_prompt.ready = True



''' General Functions '''

def exit_with_msg(msg):
	print(f"[{DEBUG}] {msg}")
	sys.exit(0)



def print_fail_and_return_to_prompt(msg):			
	print(f'\r[{FAILED}] {msg}')
	Main_prompt.rst_prompt(force_rst = True)



def print_shadow(msg):
	print(f'{GRAY}{msg}{END}')



def print_debug(msg):
	print(f'\r[{DEBUG}] {msg}')



def chill():
	pass


def get_random_str(length):
	# choose from all lowercase letter
	chars = string.ascii_lowercase + string.digits
	rand_str = ''.join(choice(chars) for i in range(length))
	return rand_str


def get_file_contents(path, mode = 'rb'):

	try:
		f = open(path, mode)
		contents = f.read()
		f.close()
		return contents

	except:
		return None



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



def parse_lhost(lhost_value):
	
	try:
		# Check if valid IP address
		lhost = str(ip_address(lhost_value))
		
	except ValueError:
		
		try:
			# Check if valid interface
			lhost = ni.ifaddresses(lhost_value)[ni.AF_INET][0]['addr']
			
		except:
			return False
	
	return lhost



def print_table(rows, columns):

	columns_list = [columns]
	
	for item in rows:

		# Values length adjustment
		try:
			for key in item.keys():
				item_to_str = str(item[key])
				item[key] = item[key] if len(item_to_str) <= 20 else f"{item_to_str[0:8]}..{item_to_str[-8:]}"

		except:
			pass

		columns_list.append([str(item[col] if item[col] is not None else '') for col in columns])
		
	col_size = [max(map(len, col)) for col in zip(*columns_list)]
	format_str = '  '.join(["{{:<{}}}".format(i) for i in col_size])
	columns_list.insert(1, ['-' * i for i in col_size])
	
	for item in columns_list:

		# Session Status ANSI
		item[-1] = f'{GREEN}{item[-1]}{END}' if item[-1] == 'Active' else item[-1]
		item[-1] = f'{ORANGE}{item[-1]}{END}' if (item[-1] in ['Unreachable', 'Undefined']) else item[-1]
		item[-1] = f'{LRED}{item[-1]}{END}' if (item[-1] in ['Lost']) else item[-1]

		# Stability ANSI
		item[-2] = f'{UNSTABLE}{item[-2]} {END}' if (columns_list[0][-2] == 'Stability' and item[-2] == 'Unstable') else item[-2]
		print(format_str.format(*item))



def clone_dict_keys(_dict):
	
	clone = deepcopy(_dict)
	clone_keys = clone.keys()
	return clone_keys



def get_terminal_columns():
    
	try:
		# Get the number of columns in the terminal
		columns = os.get_terminal_size().columns
		return columns
	
	except:
		# If there was an error, return a default value
		return 80 



def strip_ansi_codes(s):
    s = re.sub('\\[([0-9]+)(;[0-9]+)*m', '', s) 
    return re.sub('\033\\[([0-9]+)(;[0-9]+)*m', '', s) 



def clean_string(input_string):
	# Remove ANSI escape sequences
	ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
	input_string = ansi_escape.sub('', input_string)
	
	# Remove non-printable characters
	printable_chars = list(range(0x20, 0x7F)) + [0x09, 0x0A, 0x0D]
	input_string = ''.join(filter(lambda x: ord(x) in printable_chars, input_string))
	
	return input_string



def ansi_codes_detected(s):
    return True if (re.search('\033\\[([0-9]+)(;[0-9]+)*m', s) or re.search('\\[([0-9]+)(;[0-9]+)*m', s)) else False



def match_regex(regex, data):

    match = regex.search(data)
    return True if match else False



def split_str_on_regex_index(regex, string):

	start_index = regex.search(string).start()
	return [string[0:start_index], string[start_index:]]



def check_list_for_duplicates(l):
	
	for elem in l:
		if l.count(elem) > 1:
			return True
			
	return False



def subtract_lists(l1, l2):
	
	set1 = set(l1)
	set2 = set(l2)
	
	result_set = set1 - set2
	result_list = list(result_set)
	
	return result_list



def print_columns(strings):
	
	columns, lines_ = os.get_terminal_size()
	mid = (len(strings) + 1) // 2
	max_length1 = max(len(s) for s in strings[:mid])
	max_length2 = max(len(s) for s in strings[mid:])

	if max_length1 + max_length2 + 4 <= columns:
		# Print the strings in two evenly spaced columns
		for i in range(mid):
			
			col1 = strings[i].ljust(max_length1)
			try: col2 = strings[i+mid].ljust(max_length2)
			except:	col2 = ''
			print(col1 + " " * 4 + col2)

	else:
		# Print the strings in one column
		max_length = max(len(s) for s in strings)

		for s in strings:
			print(s.ljust(max_length))

	print('\n', end='')



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
