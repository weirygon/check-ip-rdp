import subprocess
import requests
import os
from datetime import datetime

filter_Score = 65
api_key = 'YOUR_OWN_API_KEY'
locate_dir = ((os.environ.get('SystemRoot')) + '\\System32\\LogFiles\\checkMaliciousIP') # %SystemRoot%\System32\LogFiles\checkMaliciousIP

def main():
    list_ips = getIPsConnected()

    for ip in list_ips:
        log(f'[*] Check: {ip}')
      
        if isMalicious(ip):
            blockIP(ip)
        else:
            log(f'[+] Allow: {ip}')

def getIPsConnected() -> list:
    
    prompt = 'netstat -tn | findstr -R "[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*:3389"'
    process = subprocess.Popen(prompt, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output, error = process.communicate()

    if error:
        print("Erro:", error.decode())
        log(f'[-] Error: {error.decode()}')

    aux = output.decode()
    
    if not aux:
        log(f'[-] Error: Not found IP in netstat!')
        exit()

    aux = aux.split()
    list_ips = list()

    if len(aux) > 5 :
        i = 2
        while( i < len(aux) ):
            list_ips.append(aux[i].split(':')[0])
            i = i + 5
    else:
        list_ips.append(aux[2].split(':')[0])

    return list_ips

def isMalicious(ip) -> bool:
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    outputJson = response.json()
    scoreIP = outputJson['data']['abuseConfidenceScore']

    if scoreIP >= filter_Score:
        log(f'[!] {ip} is malicious! Score: {scoreIP}')
        return True
    else:
        log(f'[ ] {ip} is NOT malicious! Score: {scoreIP}')
        return False

def blockIP(ip):
    
    if checkAlreadyBlock(ip):
        log(f'[+] Blocked: {ip} is already blocked!')

    else:    
        prompt = f'netsh advfirewall firewall add rule name="Malicious IP - {ip}" dir=in action=block remoteip={ip}'
        process = subprocess.Popen(prompt, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        output, error = process.communicate()

        if error:
            print("Erro:", error.decode())
            log(f'[-] Error: {error.decode()}')
            exit(1)
        log(f'[+] Block: {ip}')
        
def checkAlreadyBlock(ip) -> bool:
    prompt = f'netsh advfirewall firewall show rule name="Malicious IP - {ip}" | findstr {ip} | find /c /v ""'
    process = subprocess.Popen(prompt, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output, error = process.communicate()

    if error:
        print("Erro:", error.decode())
        log(f'[-] Error: {error.decode()}')
        exit(1)
    
    if (int((output.decode()).split()[0])):
        return True
    else:
        return False 

def log(text: str):
    
    checkDirLog()

    time = datetime.now()
    with open(f'{locate_dir}\\checkIP.log','a') as file:
        file.write(f'{time} {text}\n')

def checkDirLog():
    if not os.path.exists(locate_dir):
        #Create directory for log files
        os.mkdir(locate_dir)

main()
