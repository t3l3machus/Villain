#!/bin/python3
#
# This script is part of the 
# Author: Panagiotis Chartas (t3l3machus)

import sys, readline, string, base64
from Crypto.Cipher import AES
from uuid import UUID

DEBUG_MODE = False

''' Colors '''
MAIN = '\001\033[1;32m\002'
GREEN = '\001\033[38;5;82m\002'
GRAY = '\001\033[38;5;246m\002'
NAME = '\001\033[38;5;228m\002'
RED = '\001\033[1;31m\002'
PLOAD = '\001\033[38;5;119m\002'
FAIL = '\001\033[1;91m\002'
ORANGE = '\033[0;38;5;214m\002'
BOLD = '\001\033[1m\002'
UNDERLINE = '\001\033[4m\002'
END = '\001\033[0m\002'

''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
WARN = f'{ORANGE}Warning{END}'
IMPORTANT = WARN = f'{ORANGE}Important{END}'
FAILED = f'{RED}Fail{END}'
DEBUG = f'{ORANGE}Debug{END}'



''' Command Prompt Settings'''

class Main_prompt:
	
	original_prompt = prompt = f"{UNDERLINE}Firaga{END} > "
	main_prompt_ready = True
	SPACE = '#>SPACE$<#'
	
	
	
	@staticmethod
	def rst_prompt(force_rst = False, prompt = prompt, prefix = '\r'):
		
		Main_prompt.main_prompt_ready = True
		sys.stdout.write(prefix + Main_prompt.prompt + readline.get_line_buffer())



	@staticmethod
	def set_main_prompt_ready():
		Main_prompt.main_prompt_ready = True



''' General Functions '''

def exit_with_msg(msg):
	print(f"[{DEBUG}] {msg}")
	sys.exit(0)



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
   format_str = '   '.join(["{{:<{}}}".format(i) for i in col_size])
   columns_list.insert(1, ['-' * i for i in col_size])
      
   for item in columns_list:
	   item[-1] = f'{GREEN}{item[-1]}{END}' if item[-1] == 'Active' else item[-1]
	   item[-1] = f'{ORANGE}{item[-1]}{END}' if (item[-1] in ['Unreachable', 'Undefined']) else item[-1]
	   print(format_str.format(*item))
   


''' Encryption '''

AES_KEY = b'3WCJa88kKmlRL5BQDh5D1CLPevLlPDZ2'
IV = b'en1Bq5y8g6RpuuB4'
SALT = '3WCJa88kKmlRL5BQDh5D1CLPevLlPDZ2'

def encrypt_msg(aes_key, msg, iv):
	enc_s = AES.new(aes_key, AES.MODE_CFB, iv)
	if type(msg) == bytes:
		cipher_text = enc_s.encrypt(msg)
	else:
		cipher_text = enc_s.encrypt(msg.encode('utf-8')) #.encode('utf-8').strip() IF BYTES ENCODE
	encoded_cipher_text = base64.b64encode(cipher_text)
	#print(f'encoded_cipher_text: {encoded_cipher_text}')
	#return encoded_cipher_text if type(encoded_cipher_text) == str else encoded_cipher_text.decode('utf-8') #.decode("utf8")
	return encoded_cipher_text

def decrypt_msg(aes_key, cipher, iv):
	# ~ print(f'{aes_key}, {cipher}, {iv}')
	decryption_suite = AES.new(aes_key, AES.MODE_CFB, iv)
	plain_text = decryption_suite.decrypt(base64.b64decode(cipher))# + b'==='
	#print(f'plain_text: {plain_text}')
	return plain_text if type(plain_text) == str else plain_text.decode('utf-8', 'ignore')


# ~ s=encrypt_msg(AES_KEY, 'yolo' ,IV)
# ~ y=decrypt_msg(AES_KEY, s ,IV)
# ~ print(f'{s}:{y}')


