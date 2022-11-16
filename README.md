# Description  
This python program aims to create reverse shell commands with a fast syntax while also copying output to clipboard.
## Setup
#### Clone the repository
```bash
  sudo git clone https://github.com/Gurguii/Reverse-shell-Generator
```  
#### Get into the project's directory
```bash
    cd Reverse-shell-Generator
```  
#### Install requirements
```bash
    pip3 install -r requirements.txt
```
## Usage
```bash
    ./rev <shell-type> <options>
```  
or  
```bash
    ./rev <informative-option>
```
### Options  

- #### Informative  
-h / --help - Displays help message and exits  
-list / --list <shell-type> - Lists different commands available for given shell type  
-listall / --listall - Lists every shell type and commands available  

- #### Shell-related  
-lp / --lport <lport> - Listening port, default 4444  
-lh / --lhost <lhost> - Listening host, IpAddr(X.X.X.X) or Iface(E.g eth0), default localhost  

- #### Encoding  
b64 - B64 encodes resulting command  
url - Url encodes resulting command  

# Examples  
#### Create a base64 encoded bash shell with desired LHOST and LPORT  
```bash
./reverse bash -lh <LHOST> -lp <LPORT> b64
```  
- You will be prompted available bash commands, choose w.e you like and voilà  

#### Create an specific bash reverse shell with desired LHOST, LPORT, and url encoded  
```bash
./reverse bash=<name> -lh <LHOST> -lp <LPORT> url
```  
- Here you won't be prompted since you are specificly choosing the command with <name>
