
---
## 🧪 Iniciando la máquina

Una vez que iniciamos la máquina, descargamos el archivo proporcionado y analizamos su contenido. Nos encontramos con un fragmento de código que contiene un diccionario de usuarios:

```python
users = {
    'HTBUser132' : [md5(b'HTBUser132').hexdigest(), 'secure123!'],
    'JohnMarcus' : [md5(b'JohnMarcus').hexdigest(), '0123456789']
}
```

Esto nos da una pista importante: los nombres de usuario se están hasheando con MD5 y se almacenan junto con la contraseña en texto claro. Ya desde aquí podemos intuir que **la validación no es segura**.

---

## 🐍 Probamos en la terminal de Python

Abrimos una consola en nuestra máquina y usamos `hashlib` para reproducir el hash MD5:

```python
>>> from hashlib import md5
>>> users = {'HTBUser132' : [md5(b'HTBUser132').hexdigest(), 'secure123!']}
>>> users
{'HTBUser132': ['cdf16ba040ec2b7ecf2d1cda3289bba9', 'secure123!']}
```

---

## 📡 Conexión con `netcat`

Nos conectamos al servicio con `netcat`:

```bash
nc <IP_MAQUINA:PUERTO>
```

Una vez conectados, usamos la siguiente estructura en JSON para iniciar sesión:

```
{"option": "login"}
{"username": "HTBUser132", "password": "secure123!"}
```

---

## 🧐 Análisis del código y descubrimiento de vulnerabilidad

Al analizar el código fuente reversado, notamos que hay una lógica sospechosa en esta sección:

```python
if [usr_hash, pwd] == v:
    if usr == db_user:
        print(f'[+] welcome, {usr} 🤖!')
    else:
        print(f"[+] what?! this was unexpected. shutting down the system :: {open('flag.txt').read()} 👽")
        exit()
```

Esta validación separa la comparación del hash MD5 (`usr_hash`) de la comparación del nombre de usuario (`usr`). Esto permite una situación peligrosa: **si conseguimos otro nombre de usuario diferente, pero que tenga el mismo hash MD5**, se ejecutará el `else` y podremos ver la **flag**.

---

## 💥 MD5 Collision Attack

Aquí es donde entra el ataque de colisión MD5. Encontramos dos cadenas que generan el mismo hash MD5:

```text
TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
```

Ambas generan **el mismo hash MD5**, pero son **cadenas distintas**. Esto es justo lo que necesitamos para explotar la lógica del programa.

---

## 📝 Registro de usuarios colisionados

Registramos dos usuarios, cada uno con una de las cadenas colisionadas:

### Primer usuario:

```
{"option": "register"}
{"username": "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "password": "password123"}
```

### Segundo usuario:

```
{"option": "register"}
{"username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "password": "password123"}
```

---

## 🔓 Autenticación para obtener la flag

Ahora tratamos de iniciar sesión con el segundo usuario:

```
{"option": "login"}
{"username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "password": "password123"}
```

Esto genera la siguiente respuesta:

```
[+] what?! this was unexpected. shutting down the system :: HTB{f33ls_g00d_f1nd1ng_4lph4num3r1c_c0ll1s10ns_fr0m_tw1tt3r_p0sts} 👽
```

🎉 ¡FLAG obtenida exitosamente gracias a una colisión de MD5!

---

## 🔍 Código Reversado

Aquí está el código completo que analizamos y aprovechamos para explotar la vulnerabilidad:

```python
from hashlib import md5
import json

'''
Formato de datos:
{
    username: [md5(username).hexdigest(), password],
    ...
}
'''
users = {
    'HTBUser132' : [md5(b'HTBUser132').hexdigest(), 'secure123!'],
    'JohnMarcus' : [md5(b'JohnMarcus').hexdigest(), '0123456789']
}

def get_option():
    return input('''
    Welcome to my login application scaredy cat! I am using MD5 to save the passwords in
the database.
                          I am more than certain that this is secure.                    
   
                                   You can't prove me wrong!          
    
    [1] Login
    [2] Register
    [3] Exit

    Option (json format) :: ''')

def main():
    while True:
        option = json.loads(get_option())

        if 'option' not in option:
            print('[-] please, enter a valid option!')
            continue

        option = option['option']
        if option == 'login':
            creds = json.loads(input('enter credentials (json format) :: '))

            usr, pwd = creds['username'], creds['password']
            usr_hash = md5(usr.encode()).hexdigest()
            for db_user, v in users.items():
                if [usr_hash, pwd] == v:
                    if usr == db_user:
                        print(f'[+] welcome, {usr} 🤖!')
                    else:
                        print(f"[+] what?! this was unexpected. shutting down the system :: {open('flag.txt').read()} 👽")
                        exit()
                    break
            else:
                print('[-] invalid username and/or password!')
        
        elif option == 'register':
            creds = json.loads(input('enter credentials (json format) :: '))

            usr, pwd = creds['username'], creds['password']
            if usr.isalnum() and pwd.isalnum():
                usr_hash = md5(usr.encode()).hexdigest()
                if usr not in users.keys():
                    users[usr] = [usr_hash, pwd]
                else:
                    print('[-] this user already exists!')
            else:
                print('[-] your credentials must contain only ascii letters and digits.')

        elif option == 'exit':
            print('byeee.')
            break

if __name__ == '__main__':
    main()
```

---

## 📌 Conclusión

Este reto nos enseña una lección importante: **no es seguro usar MD5 para validar autenticaciones**, y mucho menos confiar únicamente en hashes para validar identidad. Las colisiones existen y pueden ser explotadas como en este caso.

---

## Recursos:
https://www.johndcook.com/blog/2024/03/20/md5-hash-collision/
