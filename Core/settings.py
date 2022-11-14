#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus) 
#
# This script is part of the Villain framework: 
# https://github.com/t3l3machus/Villain


from threading import BoundedSemaphore


class Threading_params:
	
	MAX_THREADS = 100
	thread_limiter = BoundedSemaphore(MAX_THREADS)



class Core_server_settings:
	
	bind_address = '0.0.0.0'
	bind_port = 65001	
	
	# How long to sleep between echo requests to check if siblings are alive
	ping_siblings_sleep_time = 4
	
	# Seconds to wait for cmd output when executing commands against shell sessions of sibling servers
	timeout_for_command_output = 30
	


class Hoaxshell_settings:
	
	bind_address = '0.0.0.0'
	bind_port = 8080
	bind_port_ssl = 443
	ssl_support = None

	# Server response header definition
	server_version = 'Apache/2.4.1'
	
	# Header name of the header that carries the backdoor's session ID
	_header = 'Authorization'
	
	# Beacon frequency of the generated backdoor shells
	default_frequency = 0.8
	
	# Generate self signed cert:
	# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
	certfile = False # Add path to cert.pem here for SSL or pass it as argument
	keyfile = False  # Add path to priv_key.pem here for SSL or pass it as argument
	
	


class Sessions_manager_settings:
	
	shell_state_change_after = 2.0 
