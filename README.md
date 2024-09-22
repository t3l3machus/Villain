# Villain
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.6-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
[![License](https://img.shields.io/badge/License-CC%20Attr--NonCommercial%204.0-red)](https://github.com/t3l3machus/Villain/blob/main/LICENSE.md)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">

## Purpose
Villain is a high-level Stage 0/1 C2 framework that can handle multiple reverse TCP and HoaxShell-based shells, enhance their functionality with additional features (commands, utilities), and share them among connected sibling servers (Villain instances running on different machines).  

The framework's main features include:
 - Payload generation based on default, customizable and/or user defined payload templates (Windows & Linux),
 - A dynamically engaged pseudo-shell prompt that can quickly swift between shell sessions,
 - File uploads (via http),
 - Fileless execution of scripts against active sessions,
 - Auto-invoke ConPtyShell against a powershell r-shell session as a new process to gain a fully interactive Windows shell,
 - Multiplayer mode,
 - Session Defender (a feature that inspects user issued commands for mistakes / unintentional input that may cause a shell to hang).
   

### Video Presentations
There’s no up-to-date presentation of Villain with its latest features, but these videos give a good overview of its functionality.  
[2022-11-30] [John Hammond](https://github.com/JohnHammond) showcased the tool in this incredible video -> [youtube.com/watch?v=pTUggbSCqA0](https://www.youtube.com/watch?v=pTUggbSCqA0)  
[2023-03-30] Version 2.0.0 release demo, made by me -> [youtube.com/watch?v=NqZEmBsLCvQ](https://www.youtube.com/watch?v=HR1KM8wrSV8)  


| :exclamation:  **Disclaimer**  |
|---------------------------------|
| **This project is in active development**. Expect breaking changes with releases. |
| Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool. |

## Preview


https://github.com/t3l3machus/Villain/assets/75489922/20bf0ad5-d06f-4658-bb43-1bb0359fe3f7




![image](https://user-images.githubusercontent.com/75489922/228979419-340918d4-3c04-48b6-913a-91aaf8756ff6.png)  

## Installation 

Villain has been explicitly developed and tested on **kali linux**. You can install it with `apt`:
```
apt install villain
```

❗New releases may take time to be incorporated into kali's repositories. 

For the latest version or if you prefer to install it manually:
```
git clone https://github.com/t3l3machus/Villain
cd ./Villain
pip3 install -r requirements.txt
```

You must also install `gnome-terminal` (required for one of the framework's commands):
```
sudo apt update&&sudo apt install gnome-terminal
```

## Usage
You should run as root:
```
villain [-h] [-p PORT] [-x HOAX_PORT] [-n NETCAT_PORT] [-f FILE_SMUGGLER_PORT] [-i] [-c CERTFILE] [-k KEYFILE] [-u] [-q] 
```

Check out the [Usage Guide](https://github.com/t3l3machus/Villain/blob/main/Usage_Guide.md) for more.  

:warning: Create your own obfuscated reverse shell templates and replace the default ones in your instance of Villain to better handle AV evasion. Here's how 📽️ -> [youtube.com/watch?v=grSBdZdUya0](https://www.youtube.com/watch?v=grSBdZdUya0)

## Contributions
Pull requests are generally welcome. Please, keep in mind: I am constantly working on new tools as well as maintaining several existing ones. I may be slow to respond.
If you have an idea for a new feature that comes with a significant chunk of code, I suggest you first contact me to discuss if there's something similar already in the making, before making a PR. 
