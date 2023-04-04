# Villain
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.6-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
[![License](https://img.shields.io/badge/License-CC%20Attr--NonCommercial%204.0-red)](https://github.com/t3l3machus/Villain/blob/main/LICENSE.md)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">

## Purpose
Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines).  

The framework's main features include:
 - Payload generation based on default, customizable and/or user defined payload templates (Windows & Linux),
 - A dynamically engaged pseudo-shell prompt that can quickly swift between shell sessions,
 - File uploads (via http),
 - Auto-http request & exec scripts against sessions (a bit unstable),
 - Auto-invoke ConPtyShell against a powershell r-shell session as a new process to gain a fully interactive Windows shell,
 - Team chat,
 - Session Defender (a feature that inspects user issued commands for mistakes / unintentional input that may cause a shell to hang)

<!--Many additional information can be found in the user guide.-->

:zap: **This release is fresh and is still being tested.**  
:warning: Create your own obfuscated reverse shell templates and replace the default ones in your instance of Villain to better handle AV evasion. Here's how 📽️ -> [youtube.com/watch?v=grSBdZdUya0](https://www.youtube.com/watch?v=grSBdZdUya0)

### Video Presentations
[2022-11-30] John Hammond showcased the tool in this incredible video -> [youtube.com/watch?v=pTUggbSCqA0](https://www.youtube.com/watch?v=pTUggbSCqA0)  
[2023-03-30] Latest release demo, made by me -> [youtube.com/watch?v=NqZEmBsLCvQ](https://www.youtube.com/watch?v=HR1KM8wrSV8)

**Disclaimer**: Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool.

## Preview
![image](https://user-images.githubusercontent.com/75489922/228979419-340918d4-3c04-48b6-913a-91aaf8756ff6.png)


## Installation & Usage
Villain has been explicitly developed and tested on **kali linux**.
```
git clone https://github.com/t3l3machus/Villain
cd ./Villain
pip3 install -r requirements.txt
```
You are going to need `gnome-terminal` for one of the framework's commands.
```
sudo apt update&&sudo apt install gnome-terminal
```
You should run as root:
```
Villain.py [-h] [-p PORT] [-x HOAX_PORT] [-n NETCAT_PORT] [-f FILE_SMUGGLER_PORT] [-c CERTFILE] [-k KEYFILE] [-u] [-q] 
```
<!--For more information about using Villain check out the [Usage Guide](https://github.com/t3l3machus/Villain/blob/main/Usage_Guide.md).-->

## Important Notes
1. The communication between sibling servers is AES encrypted using the recipient sibling server's ID as the encryption KEY and the 16 first bytes of the local server's ID as IV. During the initial connection handshake of two sibling servers, each server's ID is exchanged clear text, meaning that the handshake could be captured and used to decrypt traffic between sibling servers. I know it's "weak" that way. It's not supposed to be super secure as this tool was designed to be used during penetration testing / red team assessments, for which this encryption schema should be enough.
2. Villain instances connected with each other (sibling servers) must be able to directly reach each other as well. I intend to add a network route mapping utility so that sibling servers can use one another as a proxy to achieve cross network communication between them.
3. HoaxShell-based payloads will work only once. An already used payload cannot be reused to establish a session.

## Latest Release Notes
- The Payload Generator class was redesigned to work by dynamically engaging payload templates with a standard structure. This makes payload generation much easier and allows users to edit the default payload templates or add their own, according to their needs & tactics. As you'll notice, most of the default templates I've added for both Windows and Linux are designed to start as new processes.
- The stability and general functionality of the pseudo-shell prompt ("shell" command) has been significantly improved.
- The "upload" and "conptyshell" commands were added.
- A new chat feature was added (you can broadcast messages to all siblings by starting a command with "#").
- The "exec" command is also improved but still kind of unstable. Someday it's gonna be doing wonders. Have a little faith.

## Contributions
Pull requests are generally welcome. Please, keep in mind: I am constantly working on new offsec tools as well as maintaining several existing ones. I rarely accept pull requests because I either have a plan for the course of a project or I evaluate that it would be hard to test and/or maintain the foreign code. It doesn't have to do with how good or bad is an idea, it's just too much work and also, I am kind of developing all these tools to learn myself.

There are parts of this project that were removed before publishing because I considered them to be buggy or hard to maintain (at this early stage).
If you have an idea for an addition that comes with a significant chunk of code, I suggest you first contact me to discuss if there's something similar already in the making, before making a PR. 
