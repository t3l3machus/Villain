#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


from threading import BoundedSemaphore
from uuid import uuid4

class Threading_params:
	
	MAX_THREADS = 100
	thread_limiter = BoundedSemaphore(MAX_THREADS)



class Core_Server_Settings:
	
	bind_address = '0.0.0.0'
	bind_port = 6501	
	
	# How long to sleep between echo requests to check if siblings are alive
	ping_siblings_sleep_time = 4
	
	# Seconds to wait for cmd output when executing commands against shell sessions of sibling servers
	timeout_for_command_output = 30
	


class Hoaxshell_Settings:
	
	bind_address = '0.0.0.0'
	bind_port = 8080
	bind_port_ssl = 443
	ssl_support = None
	monitor_shell_state_freq = 3

	# Server response header definition
	server_version = 'Apache/2.4.1'
	
	# Header name of the header that carries the backdoor's session ID
	_header = 'Authorization'
	
	# Generate self signed cert:
	# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
	certfile = False # Add path to cert.pem here for SSL or parse it with -c
	keyfile = False  # Add path to priv_key.pem here for SSL or parse it with -k
	


class File_Smuggler_Settings:
	
	bind_address = '0.0.0.0'
	bind_port = 8888	



class Sessions_manager_settings:
	
	shell_state_change_after = 2.0 



class TCP_Sock_Handler_Settings:
	
	bind_address = '0.0.0.0'
	bind_port = 4443
	sentinel_value = uuid4().hex
	sock_timeout = 4
	recv_timeout = 14
	recv_timeout_buffer_size = 4096
	await_execution_timeout = 90
	alive_echo_exec_timeout = 2.5
	
	# Max failed echo response requests before a connection is characterized as lost
	fail_count = 3



class Payload_Generator_Settings:
	
	# Set to false in order to parse domains as LHOST when generating commands
	validate_lhost_as_ip = True	