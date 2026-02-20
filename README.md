# Shellerator

Shellerator is a simple CLI/TUI tool aimed to help pentesters quickly generate reverse, bind and web shells in multiple programming languages like Bash, Powershell, Netcat, PHP, ASPX, etc.    

Another similar project for the generation of one-line file downloading commands is based on this code [Uberfile](https://github.com/ShutdownRepo/uberfile)

This project is installed by default on the hacking environment [Exegol](https://github.com/ShutdownRepo/Exegol)

# Installation

Shellerator can easily be installed using `pipx` or `uv`.  

## Pipx

To install Shellerator with `pipx`, run this command:  

```
pipx install git+https://github.com/ShutdownRepo/shellerator
```

## Uv

To install Shellerator with `uv`, run this command:  

```
uv tool install git+https://github.com/ShutdownRepo/shellerator
```

# Usage

```
usage: shellerator [-h] [-l] [-b | -r | -w] [-v] [-t TYPE] [-lp LPORT] [-lh LHOST]

Easily generate reverse, bind and webshells

options:
  -h, --help                show this help message and exit
  -l, --list                Display all type of shells supported by Shellerator
  -b, --bind-shell          Generate a bind shell (you connect to the target)
  -r, --reverse-shell       Generate a reverse shell (the target connects to you) (Default)
  -w, --web-shell           Generate a webshell
  -v, --verbose             Enable verbosity

Bindshell options:
  -t TYPE, --type TYPE      Type of shell to generate
  -lp LPORT, --lport LPORT  Listener Port

Reverse shell options:
  -t TYPE, --type TYPE      Type of shell to generate
  -lp LPORT, --lport LPORT  Listener Port
  -lh LHOST, --lhost LHOST  Listener IP address

Webshell options:
  -t TYPE, --type TYPE      Type of shell to generate
```

Shellerator will automatically start a TUI (Terminal User Interface) when a required option is omitted.  

## Generate a Powershell reverse shell using the TUI

![PowerShell Reverse Shell TUI](assets/powershell_revshell_tui.gif)

## Generate a PHP webshell

![Netcat Bindshell](assets/php_webshell_cli.gif)


## Generate a Netcat bindshell

![Netcat Bindshell](assets/netcat_bindshell_cli.gif)

# Sources & credits

This project is inspired by [Print-My-Shell](https://github.com/sameera-madushan/Print-My-Shell/)  

Some commands come from the following sources:  

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
