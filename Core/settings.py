from threading import BoundedSemaphore


class Threading_params:
	
	MAX_THREADS = 100
	thread_limiter = BoundedSemaphore(MAX_THREADS)



class Core_server_settings:
	
	bind_address = '0.0.0.0'
	bind_port = 65001	
	# How long to sleep between echo requests to check if siblings are alive
	ping_siblings_sleep_time = 5 



class Hoaxshell_settings:
	
	bind_address = '0.0.0.0'
	bind_port = 65002
	_header = 'Authorization' # Header name of the header that carries the rshell's SID
	default_frequency = 0.8   # Beacon loop frequency of the rshells
	certfile = False # Add path to cert.pem here for SSL
	keyfile = False  # Add path to priv_key.pem here for SSL



class Sessions_manager_settings:
	
	shell_state_change_after = 4.0 
