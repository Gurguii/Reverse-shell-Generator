# Reverse-shell-Generator
Generates a reverse shell, allows URL encoding and copies the shell in your clipboard. 
## Quick usage

#### Clone the repository (or just copy-paste)
```bash
  sudo git clone https://github.com/Gurguii/Reverse-shell-Generator
```
#### Run the script
```bash
    python3 reverse.py -sh < bash|netcat|php|ruby|perl|python > -lh <lhost> -lp* <lport> -enc*
```  
**Note:** default LPORT is 4444, params with * are optional.

## Test 
- Created reverse shell:
```bashi
  hack@hack:~$ python3 reverse.py -sh netcat -lh localhost
```
![alt text](https://media.giphy.com/media/2EHmBCMSL0fhbdAoF5/giphy.gif)
