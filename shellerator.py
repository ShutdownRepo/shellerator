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
import json
import socket
import base64
import signal
import ipaddress
import os

import psutil
from colorama import Fore
from colorama import Style
import platform
if platform.system() == 'Windows':
    from consolemenu import *
else:
    from simple_term_menu import TerminalMenu

def signal_handler(sig, frame):
    exit(1)

# Handle Ctrl+C key interruption
signal.signal(signal.SIGINT, signal_handler)

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

def check_shell_args(shells, args):
    # Check if the shell type specified by the user is supported by Shellerator
    try:
        shells[args.SHELLTYPE][args.TYPE]
    except KeyError:
        sys.exit(f"{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} No {args.SHELLTYPE} found for {Fore.RED + Style.BRIGHT}{args.TYPE}{Style.RESET_ALL}! Please run '{Fore.YELLOW + Style.BRIGHT}shellerator -l{Style.RESET_ALL}' to list the supported type of shells!")

    # Check if the port number specified by the user is correct (The check is done for reverse/bind shells)
    if args.SHELLTYPE != "webshells":
        try:
            if int(args.LPORT) < 1 or int(args.LPORT) > 65535:
                raise ValueError
        except ValueError:
            sys.exit(f"{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} Port number must be between 1 and 65535")

        # Check if the IP address specified by the user is an IPv4 (The check is only done for reverse shells)
        if args.SHELLTYPE != "bindshells":
            try:
                ip_addr = ipaddress.ip_address(args.LHOST)
            except ValueError:
                sys.exit(f"{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {args.LHOST} does not appear to be an IPv4")

def list_shells(revshells, bindshells, webshells):
    print(f"{Fore.BLUE + Style.BRIGHT}Reverse shells{Style.RESET_ALL}")
    for revshell in sorted(revshells.keys()):
        print(f"   - {revshell}")
    print(f"\n{Fore.BLUE + Style.BRIGHT}Bindshells{Style.RESET_ALL}")
    for bindshell in sorted(bindshells.keys()):
        print(f"   - {bindshell}")
    print(f"\n{Fore.BLUE + Style.BRIGHT}Webshells{Style.RESET_ALL}")
    for webshell in sorted(webshells.keys()):
        print(f"   - {webshell}")

# Return list of listeners for reverse shells
def get_listeners(lport, verbosity=False):
    listeners = {
        'netcat': f"nc -nlvp {lport}",
        'rlwrap + nc': f"rlwrap -cAr nc -nlvp {lport}",
        'penelope': f"penelope -p {lport}",
        'ConPty': f"stty raw -echo; (stty size; cat) | nc -nlvp {lport}",
        'pwncat (linux)': f"pwncat-cs -lp {lport}",
        'pwncat (windows)': f"python3 -m pwncat -m windows -lp {lport}",
        'socat': f'socat file:`tty`,raw,echo=0 TCP-L:{lport}',
        'ncat (TLS)': f'ncat --ssl -lvnp {lport}',
        'busybox nc': f'busybox nc -lp {lport}',
        'powercat': f"powercat -l -p {lport}"
    }
    comments = {
        'rlwrap + nc': f" {Fore.YELLOW + Style.BRIGHT}(Simple alternative for upgrading Windows reverse shells){Style.RESET_ALL}",
        'penelope': f" {Fore.YELLOW + Style.BRIGHT}(Great for upgrading Linux reverse shells){Style.RESET_ALL}",
        'ConPty': f" {Fore.YELLOW + Style.BRIGHT}(Great for upgrading Windows reverse shells){Style.RESET_ALL}",
        'socat': f" {Fore.YELLOW + Style.BRIGHT}(Provide a fully interactive TTY. The Linux target must have Socat installed){Style.RESET_ALL}"
    }

    return {
        listener: command + (comments.get(listener, "") if verbosity else "") for listener, command in listeners.items()
    }
    
def format_shell(shell_index, shell, comment):
    return f"{Fore.BLUE + Style.BRIGHT}[{str(shell_index + 1)}]{Style.RESET_ALL} {shell.strip()}{Fore.YELLOW + Style.BRIGHT} ({comment}){Style.RESET_ALL}" if comment.strip() else f"{Fore.BLUE + Style.BRIGHT}[{str(shell_index + 1)}]{Style.RESET_ALL} {shell.strip()}"

def upgrade_tty(verbosity=False):
    if verbosity:
        return f"""\n{Fore.RED + Style.BRIGHT}[Upgrade your TTY]{Style.RESET_ALL}
{Fore.BLUE + Style.BRIGHT}[1]{Style.RESET_ALL} Execute one of the following commands from your reverse shell to obtain a TTY:
python -c 'import pty; pty.spawn("/bin/bash")'
script -q /dev/null -c /bin/bash
-- 
{Fore.BLUE + Style.BRIGHT}[2]{Style.RESET_ALL} Press {Fore.YELLOW + Style.BRIGHT}Ctrl+Z{Style.RESET_ALL} to background your TTY, then run:
stty size{Style.RESET_ALL} {Fore.YELLOW + Style.BRIGHT}(Returns the rows and columns of your current terminal window){Style.RESET_ALL}
stty raw -echo; fg{Style.RESET_ALL} {Fore.YELLOW + Style.BRIGHT}(Prevents commands to be echoed, enables tab completion, handles Ctrl+C, etc.){Style.RESET_ALL}
Press {Fore.YELLOW + Style.BRIGHT}[ENTER]{Style.RESET_ALL} to continue
--
{Fore.BLUE + Style.BRIGHT}[3]{Style.RESET_ALL} Reset your shell, export the SHELL and TERM environment variables, and set a proper terminal size to avoid text overlapping:
reset
export SHELL=bash
export TERM=xterm-256color
stty rows `<rows>` columns `<columns>`{Style.RESET_ALL} {Fore.YELLOW + Style.BRIGHT}(Replace `<rows>` and `<columns>` with the values returned by `stty size`){Style.RESET_ALL}
"""
    else :
        return f"""\n{Fore.RED + Style.BRIGHT}[Upgrade your TTY]{Style.RESET_ALL}
{Fore.BLUE + Style.BRIGHT}[1]{Style.RESET_ALL} Execute any of the following commands from your reverse shell to obtain a TTY:
python -c 'import pty; pty.spawn("/bin/bash")'
script -q /dev/null -c /bin/bash{Style.RESET_ALL}
-
{Fore.BLUE + Style.BRIGHT}[2]{Style.RESET_ALL} Press {Fore.YELLOW + Style.BRIGHT}Ctrl+Z{Style.RESET_ALL} to background your TTY, then run:
stty size
stty raw -echo; fg
Press {Fore.YELLOW + Style.BRIGHT}[ENTER]{Style.RESET_ALL} to continue
-
{Fore.BLUE + Style.BRIGHT}[3]{Style.RESET_ALL} Reset your shell, export the SHELL and TERM environment variables, and set a proper terminal size to avoid text overlapping:
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <rows> columns <columns>
    """
      
def main():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(BASE_DIR, "data", "shells.json")) as f:
        shells=json.load(f)
    revshells = shells['revshells']
    bindshells = shells['bindshells']
    webshells = shells['webshells']

    parser = argparse.ArgumentParser(description='Easily generate reverse, bind and webshells', formatter_class=lambda prog: argparse.HelpFormatter(prog, width=100, max_help_position=40))
    parser.add_argument('-l', '--list', dest='LIST', action='store_true', help='Display all type of shells supported by Shellerator')
    # Can't choose bind shell, reverse shell and webshell simultaneously
    shelltype = parser.add_mutually_exclusive_group()
    shelltype.add_argument('-b', '--bind-shell', dest='SHELLTYPE', action='store_const', const='bindshells', help='Generate a bind shell (you connect to the target)')
    shelltype.add_argument('-r', '--reverse-shell', dest='SHELLTYPE', action='store_const', const='revshells', help='Generate a reverse shell (the target connects to you) (Default)')
    shelltype.add_argument('-wsh', '--web-shell', dest='SHELLTYPE', action='store_const', const='webshells', help='Generate a webshell')
    parser.add_argument('-v','--verbose', action='store_true', help="Enable verbosity")
    # Sets reverse shell as the default shell type
    parser.set_defaults(SHELLTYPE='revshells')
    # Creates group of options for bindshell
    bindshell = parser.add_argument_group('Bindshell options')
    # typeoption, portoption  are required for bindshells and revshells (https://stackoverflow.com/questions/23775378/allowing-same-option-in-different-argparser-group)
    typeoption = bindshell.add_argument('-t', '--type', dest='TYPE', type=str.lower, help='Type of shell to generate')
    portoption = bindshell.add_argument('-lp', '--lport', dest='LPORT', type=str, help='Listener Port')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell._group_actions.append(portoption)
    revshell.add_argument('-lh', '--lhost', dest='LHOST', type=str, help='Listener IP address')
    # Only the shell type is required for webshells
    webshell = parser.add_argument_group('Webshell options')
    webshell._group_actions.append(typeoption)
    args = parser.parse_args()
    if args.LIST:
        list_shells(revshells, bindshells, webshells)
        sys.exit(0)
    if args.SHELLTYPE == 'revshells' and not args.LHOST:
        args.LHOST = select_address()
    if args.SHELLTYPE != 'webshells' and not args.LPORT:
        menu_list = [
            'HTTP (80)',
            'HTTPS (443)',
            'DNS (53)',
            'L33t (1337)'
        ]
        args.LPORT = menu_with_custom_choice("Listener port?", menu_list)
    if not args.TYPE:
        if args.SHELLTYPE == 'revshells':
            menu_list = sorted(revshells.keys())
        elif args.SHELLTYPE == "bindshells":
            menu_list = sorted(bindshells.keys())
        else:
            menu_list = sorted(webshells.keys())
        args.TYPE = menu('What type of shell do you want?', menu_list)
    
    # Check user specified arguments (shell type, port number and IP address)
    check_shell_args(shells, args)

    print(f"{Fore.RED + Style.BRIGHT}[{args.SHELLTYPE.capitalize()}]{Style.RESET_ALL}")
    if args.SHELLTYPE == "revshells":
        for shell_index, revshell in enumerate(revshells[args.TYPE]):
            shell = revshell['command'].replace('{LHOST}', args.LHOST).replace('{LPORT}', args.LPORT)
            comment = revshell['comments'].strip()
            if args.TYPE == "powershell" and shell_index == 4:
                shell_utf16 = revshells[args.TYPE][0]['command'].replace("'",'"').replace('{LHOST}', args.LHOST).replace('{LPORT}', args.LPORT).encode('utf-16le')
                # pwsh_base64_revshell
                shell = "powershell -e " + base64.b64encode(shell_utf16).decode()
            if shell:
                print(format_shell(shell_index, shell, comment))
        # Display listeners
        print(f"\n{Fore.RED + Style.BRIGHT}[Listeners] {Style.RESET_ALL}")
        listeners = get_listeners(args.LPORT, args.verbose)
        for listener_index, command in enumerate(listeners):
            print(f"{Fore.BLUE + Style.BRIGHT}[{listener_index + 1}]{Style.RESET_ALL} {command}: {listeners[command]}")
        # Display help menu for upgrading the TTY
        print(upgrade_tty(args.verbose))
    elif args.SHELLTYPE == "bindshells":
        for shell_index, bindshell in enumerate(bindshells[args.TYPE]):
            shell = bindshell['command'].replace('{LPORT}', args.LPORT)
            comment = bindshell['comments'].strip()
            print(format_shell(shell_index, shell, comment))
        print(upgrade_tty(args.verbose))
    else:
        for shell_index, webshell in enumerate(webshells[args.TYPE]):
            shell = webshell['command']
            comment = webshell['comments'].strip()
            print(format_shell(shell_index, shell, comment))
        print(upgrade_tty(args.verbose))

if __name__ == '__main__':
    main()
