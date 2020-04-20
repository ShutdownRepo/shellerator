# Shellerator
  Shellerator is a simple command-line tool aimed to help pentesters quickly generate one-liner reverse/bind shells in multiple languages (Bash, Powershell, Java, Python...).
  This project is inspired by [Print-My-Shell](https://github.com/sameera-madushan/Print-My-Shell/). I just rewrote it and added some options and glitter to it.
  **The lists of reverse and bind shells are not perfect yet. I'll work on this when I have the time to. I'll be happy to review pull requests too :)**

  ![Example (with menus)](https://raw.githubusercontent.com/ShutdownRepo/shellerator/master/assets/example-menus.gif)

# Install
  The install is pretty simple, just clone this git and install the requirements.
  ```
  git clone https://github.com/ShutdownRepo/shellerator
  pip3 install --user -r requirements.txt
  ```

# Usage
  Usage is dead simple too.
  ```
  usage: shellerator.py [-h] [-b | -r] [-t TYPE] [-p LPORT] [-i LHOST]

  Generate a bind/reverse shell

  optional arguments:
    -h, --help              show this help message and exit
    -l, --list            Print all the types of shells shellerator can generate
    -b, --bind-shell        Generate a bind shell (you connect to the target)
    -r, --reverse-shell     Generate a reverse shell (the target connects to you)(Default)

  Bind shell options:
    -t TYPE, --type TYPE    Type of the shell to generate (Bash, Powershell, Java...)
    -p LPORT, --port LPORT  Listener Port

  Reverse shell options:
    -t TYPE, --type TYPE    Type of the shell to generate (Bash, Powershell, Java...)
    -i LHOST, --ip LHOST    Listener IP address
    -p LPORT, --port LPORT  Listener Port
  ```

## Without CLI menus
  If you already know what type of shell you want to generate and don't have time to select the language in the beautiful CLI menu, you can set it with the appropriate `-t` (or `--type`) option.
  ```
  python3 shellerator.py [-r | -b] -t/--type bash -i/--ip 192.168.56.1 -p/--port 1337
  ```
  ![Example (without menus)](https://raw.githubusercontent.com/ShutdownRepo/shellerator/master/assets/example-no-menus.gif)

# To-Do List
## Things to add
  Here are some things to add that I have in mind, I'll work on that asap
  - Add bindshells
  - Add encrypted shells and separate them from bind/rev ?
  - Add some kind of option to help user get info on how to improve shell/tty (rlwrap, stty, ConPty (cf. PayloadsAllTheThings))

# Sources
  Shells mostly come from the following links
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  - http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
  - https://ashr.net/bind/and/reverse/shell/cheatsheet/windows/and/linux.aspx
