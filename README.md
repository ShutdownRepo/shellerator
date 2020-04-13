# Shellerator
  Shellerator is a simple command-line tool aimed to help pentesters quickly generate one-liner reverse/bind shells in multiple languages (Bash, Powershell, Java, Python...).
  This project is inspired by [Print-My-Shell](https://github.com/sameera-madushan/Print-My-Shell/). I just rewrote it and added some options and glitter to it.
  **The dictionnaries of reverse and bind shells is not perfect yet. I'll work on this when I have time to. I'll be happy to review pull requests/requests too**

# Install
  The install is pretty simple, just clone this git and install the requirements.
  ```
  git clone https://github.com/ShutdownRepo/shellerator
  pip3 install --user -r requirements.txt
  ```

# Usage
  Usage is dead simple too.
  ![Usage screenshot](https://i.imgur.com/iDAZDIB.png)

## Bind shell
  ```
  python3 shellerator.py --bind-shell --port 1337
  ```
## Reverse shell
  If you want to generate reverse shells (choice by default), you'll need to supply the listener IP address and port.
  ```
  python3 shellerator.py -i/--ip 192.168.56.1 -p/--port 1337
  python3 shellerator.py -r/--reverse-shell -i/--ip 192.168.56.1 -p/--port 1337
  ```
## Without a CLI menu
  If you already know what type of shell you want to generate and don't have time to select the type in a beautiful CLI menu, you can set the type with the appropriate option.
  ```
  python3 shellerator.py [-r | -b] -t/--type bash -i/--ip 192.168.56.1 -p/--port 1337
  ```

# To-Do List
## Things to add
  Here are some things to add that I have in mind, I'll work on that asap
  - Add a `-l/--list` option for bind/revshell to list the types of shell in the DB (php, python, powershell, bash and so on)
  - Add an asciinema to this readme and populate the readme a bit more ?

# Sources
  Shells mostly come from the following links
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  - http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
