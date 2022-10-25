from threading import BoundedSemaphore


class Threading_params:
	
	MAX_THREADS = 100
	thread_limiter = BoundedSemaphore(MAX_THREADS)



class Core_server_settings:
	
	# How long to sleep between echo requests to check if siblings are alive
	ping_siblings_sleep_time = 5 



class Sessions_manager_settings:
	
	shell_state_change_after = 5.0 
