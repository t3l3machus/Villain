#! /bin/python3
#
# This script is part of the Sauron penetration testing framework.  
# Author: Panagiotis Chartas (t3l3machus)
# Usage: python3 host.py path lhost 

import ssl, os, re
from threading import Thread, Event
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from stat import S_ISCHR, ST_MODE, S_ISBLK, S_ISFIFO, S_ISSOCK
from platform import system as get_system_type
from sys import exit as _exit, argv
from warnings import filterwarnings
import netifaces as ni

filterwarnings("ignore", category = DeprecationWarning)


# ---------- Eviltree -----------#

def move_on():
	pass


''' Colors '''
LINK = '\033[1;38;5;37m'
BROKEN = '\033[48;5;234m\033[1;31m'
CHARSPEC = '\033[0;38;5;228m'
#CHARSPEC = '\033[48;5;234m\033[1;33m'
#PIPE = '\033[38;5;214m'
PIPE = '\033[48;5;234m\033[1;30m'
SOCKET = '\033[1;38;5;98m'
EXECUTABLE = '\033[1;38;5;43m'
DENIED = '\033[38;5;222m'
DEBUG = '\033[0;38;5;214m'
GREEN = '\033[38;5;47m'
DIR = '\033[1;38;5;12m'
MATCH = '\033[1;38;5;201m'
FAILED = '\033[1;31m'
END = '\033[0m'
BOLD = '\033[1m'

path = argv[1]
path = path if path[-1] == os.sep else path + os.sep
iface = argv[2].lower()
lhost = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
level = 4096
ASCII = False
follow_links = True

# File extensions to exclude from the web tree
hide_extensions = ['zip', 'txt', 'rar', 'tar', 'gz', 'html', 'css', 'font', 'doc', 'docx', 'csv', 'xls', \
'xlsx', 'pdf', 'pack', 'idx', 'sample', 'gif', 'png', 'jpeg', 'jpg', 'md', 'dmp', '7z', 'bz2', 'xz', 'deb', \
'img', 'iso', 'vmdk', 'ovf', 'ova', 'egg', 'log', 'otf', 'mp3', 'mp4', 'conf']

# Directories extensions to exclude from the web tree
hide_dirs = ['.git']

def exit_with_msg(msg):
	print('[' + DEBUG + 'Debugger' + END + '] ' + msg)
	_exit(1)


# Define depth level
if isinstance(level, int):
	depth_level = level if (level > 0) else exit_with_msg('Level (-L) must be greater than 0.') 

else:
	depth_level = 4096


# -------------- Functions -------------- #
def load_file(file_path, mode):
	f = open(file_path, mode)
	content = f.read()
	f.close()
	return content	



def decoder(l):
	
	decoded = []
	
	for item in l:
		if isinstance(item, bytes):
			decoded.append(item.decode('utf-8', 'ignore'))
		else:
			decoded.append(item)
			
	return decoded

	

def fake2realpath(path, target):
	
	sep_count = target.count(".." + os.sep)
	regex_chk_1 = "^" + re.escape(".." + os.sep)
	regex1_chk_2 = "^" + re.escape("." + os.sep)
	regex1_chk_3 = "^" + re.escape(os.sep)
	
	if (re.search(regex_chk_1, target)) and (sep_count <= (path.count(os.sep) - 1)):
		dirlist = [d for d in path.split(os.sep) if d.strip()]
		dirlist.insert(0, os.sep)

		try:
			realpath = ''

			for i in range(0, len(dirlist) - sep_count ):
				realpath = realpath + (dirlist[i] + os.sep) if dirlist[i] != "/" else dirlist[i]

			realpath += target.split(".." + os.sep)[-1]
			return str(Path(realpath).resolve())
			
		except:
			return None

	elif re.search(regex1_chk_2, target):
		return str(Path((path + (target.replace("." + os.sep, "")))).resolve())
	
	elif not re.search(regex1_chk_3, target):
		return str(Path(path + target).resolve())
	
	else:
		return str(Path(target).resolve())



def adjustUnicodeError():
	exit_with_msg('The system seems to have an uncommon default encoding. Restart eviltree with options -q and -A to resolve this issue.')

child = (chr(9500) + (chr(9472) * 2) + ' ') if not ASCII else '|-- '
child_last = (chr(9492) + (chr(9472) * 2) + ' ') if not ASCII else '\-- '
parent = (chr(9474) + '   ') if not ASCII else '|   '
total_dirs_processed = 0
total_files_processed = 0



def eviltree(root_dir, intent = 0, depth = '', depth_level = depth_level):

	try:
		global total_dirs_processed, total_files_processed, path, lhost
		root_dirs = next(os.walk(root_dir))[1]
		root_files = next(os.walk(root_dir))[2]
		total_dirs = len(root_dirs)
		total_files = len(root_files)
		symlinks = []
		recursive = []
		print('\r' + BOLD + GREEN + root_dir + END + ' (web root)') if not intent else move_on()


		''' Handle symlinks '''
		for d in root_dirs:
			if os.path.islink(root_dir + d):
				symlinks.append(d)
		
		
		''' Process files '''
		root_files.sort()
		
		for i in range(0, total_files):
			
			total_files_processed += 1
			
			if root_files[i].count('.'):
				ext = root_files[i].rsplit('.', 1)[-1]
				if ext.lower() in hide_extensions:
					continue
			
			file_path = root_dir + root_files[i]
			is_link = True if os.path.islink(file_path) else False
				
			try:
				is_char_special = True if S_ISCHR((os.lstat(file_path)[ST_MODE])) else False
			except:
				is_char_special = False
			
			try:
				is_block_special = True if S_ISBLK(os.stat(file_path)[ST_MODE]) else False
			except:
				is_block_special = False

			try:
				is_pipe = True if S_ISFIFO(os.stat(file_path).st_mode) else False
			except:
				is_pipe = False

			try:
				is_socket = True if S_ISSOCK(os.stat(file_path).st_mode) else False
			except:
				is_socket = False

			try:
				is_executable = True if (os.access(file_path, os.X_OK) and not is_char_special and not is_block_special and not is_pipe and not is_socket) else False
			except:
				is_executable = False
					

			
			''' Verify target path if file is a symlink '''		
			if is_link:
									
				symlink_target = target = os.readlink(file_path) if is_link else None
				target = fake2realpath(root_dir, target)
				is_dir = True if os.path.isdir(str(target)) else False
				is_broken = True if (not os.path.exists(str(target)) or is_dir) else False
				
				if not WINDOWS:
					
					try:
						target_is_char_special = True if S_ISCHR((os.lstat(target)[ST_MODE])) else False
					except:
						target_is_char_special = False
						
					try:
						target_is_block_special = True if S_ISBLK(os.stat(target).st_mode) else False
					except:
						target_is_block_special = False

					try:
						target_is_pipe = True if S_ISFIFO(os.stat(target).st_mode) else False
					except:
						target_is_pipe = False

					try:
						target_is_socket = True if S_ISSOCK(os.stat(target).st_mode) else False
					except:
						target_is_socket = False

					try:
						target_is_executable = True if (os.access(target, os.X_OK) and not target_is_char_special and not target_is_block_special and not target_is_pipe and not target_is_socket) else False
					except:
						target_is_executable = False
				
				else:
					target_is_executable, target_is_socket, target_is_pipe, target_is_block_special, target_is_char_special = False, False, False, False, False
				
			else:
				is_broken = None
			
							
			''' Color mark and print file accordingly in relation to its type and content inspection results '''

			color = ''
			
			if is_link:				
				linkcolor = BROKEN if is_broken else LINK
				color = CHARSPEC if target_is_block_special or target_is_char_special else color
				color = PIPE if target_is_pipe else color
				color = SOCKET if target_is_socket else color
				color = EXECUTABLE if target_is_executable else color
				filename = (linkcolor + root_dir.replace(path, '') + root_files[i] + END + ' -> ' + color + symlink_target + errormsg)
			
			# ~ elif is_char_special or is_block_special:
				# ~ filename = (CHARSPEC + root_dir + root_files[i])

			# ~ elif is_pipe:
				# ~ filename = (PIPE + root_dir + root_files[i])

			# ~ elif is_socket:
				# ~ filename = (SOCKET + root_dir + root_files[i])

			# ~ elif is_executable:
				# ~ filename = (EXECUTABLE + root_dir + root_files[i])

			else:			
				#filename = (color + 'http://' + lhost + '/' + root_dir.replace(path, '') + root_files[i])
				filename = ('http://' + lhost + '/' + root_dir.replace(path, '') + EXECUTABLE + root_files[i] + END)

			''' Print file branch '''
			print(depth + child + color + filename + END) if (i < (total_files + total_dirs) - 1) else print(depth + child_last + color + filename + END)
					


		''' Process dirs '''
		root_dirs.sort()
		
		for i in range(0, total_dirs):
			
			total_dirs_processed += 1
			#joined_path = root_dir + root_dirs[i]
			if root_dirs[i] in hide_dirs:
				continue
			
			joined_path = root_dir + root_dirs[i]
			is_recursive = False
			directory = (root_dirs[i] + os.sep)
						
			''' Access permissions check '''
			try:
				sub_dirs = len(next(os.walk(joined_path))[1])
				sub_files = len(next(os.walk(joined_path))[2])
				errormsg = ''
			
			except StopIteration:
				sub_dirs, sub_files = 0, 0
				errormsg = ' [error accessing dir]'
						
			
			''' Check if symlink and if target leads to recursion '''
			if root_dirs[i] in symlinks:
				symlink_target = target = os.readlink(joined_path)
				target = fake2realpath(root_dir, target)			
				is_recursive = ' [recursive, not followed]' if target == root_dir[0:-1] else ''
				
				if len(is_recursive):
					recursive.append(joined_path)
					
				print(depth + child + LINK + directory + END + ' -> ' + DIR + symlink_target + END + is_recursive + errormsg) if i < total_dirs - 1 else print(depth + child_last + LINK + directory + END + ' -> ' + DIR + symlink_target + END + is_recursive + errormsg)
				
			else:
				print(depth + child + DIR + directory + END + errormsg) if i < total_dirs - 1 else print(depth + child_last + DIR + directory + END + errormsg)

			''' Iterate next dir '''
			if (not follow_links and root_dirs[i] not in symlinks) or (follow_links and not is_recursive):
				if (sub_dirs or sub_files) and (intent + 1) < depth_level:
					tmp = depth
					depth = depth + parent if i < (total_dirs - 1) else depth + '	'
					eviltree(joined_path + os.sep, intent + 1, depth)
					depth = tmp
			

	except StopIteration:
		print('\r' + DIR + root_dir + END + ' [error accessing dir]')
		
	except UnicodeEncodeError:
		adjustUnicodeError()

	except KeyboardInterrupt:
		exit_with_msg('Keyboard interrupt.')
		
	except Exception as e:
		exit_with_msg('Something went wrong. Consider creating an issue about this in the original repo (https://github.com/t3l3machus/eviltree)\n' + BOLD + 'Error Details' + END +': ' + str(e))



# -------------- http Server -------------- #
class HTTPRequestHandler(BaseHTTPRequestHandler):
	
	global path
	
	def do_GET(self):

		# ~ self.send_response(200)
		# ~ self.send_header("Content-Type", 'application/octet-stream')
		# ~ self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(os.path.basename(FILEPATH)))
		# ~ fs = os.fstat(f.fileno())
		# ~ self.send_header("Content-Length", str(fs.st_size))
		# ~ self.end_headers()

		# ~ try:
			
		# ~ requested_resource = open(os.path.dirname(os.path.abspath(__file__)) + self.path, 'rb')
		requested_resource = open(path[0:-1] + self.path, 'rb')
		data = requested_resource.read()
		requested_resource.close()
		self.send_response(200)
		self.send_header('Access-Control-Allow-Origin', '*')
		self.end_headers()
		self.wfile.write(bytes(data))
		return
		# ~ except:
			# ~ self.send_response(404)
			# ~ self.end_headers()
			# ~ self.wfile.write(bytes('NOT FOUND', "utf-8"))
				
			
		
	def do_PUT(self):
		
		path = self.translate_path(self.path)
		
		if path.endswith('/'):
			self.send_response(405, "Method Not Allowed")
			self.wfile.write("PUT not allowed on a directory\n".encode())
			return
			
		else:
			
			try:
				os.makedirs(os.path.dirname(path))
				
			except FileExistsError: 
				pass
				
			length = int(self.headers['Content-Length'])
			
			with open(path, 'wb') as f:
				f.write(self.rfile.read(length))
				
			self.send_response(201, "Created")



def make_webtree(path):
	
	root_dir = path if path[-1] == os.sep else path + os.sep	

	if os.path.exists(root_dir):
		eviltree(root_dir)
		#print('\n' + str(total_dirs_processed) + ' directories, ' + str(total_files_processed) + ' files')
		
	else:
		exit_with_msg('Directory does not exist.')

	
	
def host_hierarchy(path, bind_address = '0.0.0.0', bind_port = 80):
	
	# Init http server
	try:
		httpd = HTTPServer((bind_address, bind_port), HTTPRequestHandler)

	except OSError:
		exit(f'\n[{FAILED}] - {BOLD}Port {bind_port} seems to already be in use.{END}\n')		
	
	httpd = Thread(target = httpd.serve_forever, args = ())
	httpd.daemon = True
	httpd.start()
	
	print(f'[{SOCKET}http-server{END}] Running on {bind_address}:{bind_port}, Interface: {lhost} (Press ENTER to exit.)')
	make_webtree(path)
	print(f'\n{DEBUG}Server access log{END}:')
	
	try:
		x = input()
		_exit(0)
		
	except KeyboardInterrupt:
		_exit(0)


host_hierarchy(path)
