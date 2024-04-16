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
import json
from colorama import Fore
from colorama import Style
import platform
if platform.system() == 'Windows':
    from consolemenu import *
else:
    from simple_term_menu import TerminalMenu

shells = []

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

def list_shells(type):
    f = open(f"payloads/{type}.json")
    shells = json.load(f)

    print(Fore.BLUE + Style.BRIGHT + 'Reverse shells' + Style.RESET_ALL)
    for shell in shells:
        if shell['direction'] == 'reverse':
            print(f"[{shell['id']}] - {shell['payload']}")
    print()
    print(Fore.BLUE + Style.BRIGHT + 'Bind shells' + Style.RESET_ALL)
    for shell in shells:
        if shell['direction'] == 'bind':
            print(f"[{shell['id']}] - {shell['payload']}")
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
    portoption = bindshell.add_argument('-lp', '--lport', dest='LPORT', type=str, help='Listener Port')
    idoption = bindshell.add_argument('--id', dest='ID', type=str, help='Only output the payload with this id')
    quietoption = bindshell.add_argument('--quiet', dest='QUIET', action='store_true', help='Only output the final payload(s)')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell.add_argument('-lh', '--lhost', dest='LHOST', type=str, help='Listener IP address')
    revshell._group_actions.append(portoption)
    options = parser.parse_args()

    if options.LIST:
        list_shells(options.TYPE)

    if options.SHELLTYPE == 'revshells' and not options.LHOST:
        options.LHOST = select_address()

    if not options.LPORT:
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

def print_shell(shell, lport, lhost):
    if options.LHOST is not None:
        shell_str = shell['payload'].replace('{LHOST}', lhost).replace('{LPORT}', lport).strip()
    else:
        shell_str = shell['payload'].replace('{LPORT}', lport).strip()

    if options.QUIET:
        return f"{shell_str}"
    else:
        return f"{Fore.BLUE} {Style.BRIGHT} [{shell['id']}] {Style.RESET_ALL} {shell_str}"


if __name__ == '__main__':
    options = get_options()
    f = open(f"payloads/{options.TYPE}.json")
    shells = json.load(f)

    for shell in shells:
        if options.ID:
            if options.ID == shell['id']:
                print(print_shell(shell, options.LPORT, options.LHOST))
        else:
            print(print_shell(shell, options.LPORT, options.LHOST))

    if options.SHELLTYPE == "revshells":
        cmdline = f'{sys.argv[0]} --reverse-shell --type {options.TYPE} --lhost {options.LHOST} --lport {options.LPORT}'
    elif options.SHELLTYPE == "bindshells":
        cmdline = f'{sys.argv[0]} --bind-shell --type {options.TYPE} --lport {options.LPORT}'
