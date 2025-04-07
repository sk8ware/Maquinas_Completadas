# HTB Crypto Challenge - RSA Factorization

---

## Descripción del Reto

Descargamos el archivo proporcionado por Hack The Box (HTB) y revisamos el sitio en el navegador usando el puerto especificado.

Al observar el código fuente del servidor, notamos que está generando dos números primos aleatorios. El sistema nos solicita el valor de:

- `p + q`
    
- Y luego nos muestra `n`, que es el producto de esos dos primos.
    

Esto nos da una pista clara: se trata de una implementación básica del algoritmo RSA.

---

## Teoría Rápida: Ataque a RSA por Factorización

En RSA, la seguridad radica en la dificultad de factorizar `n` en sus primos `p` y `q`:

```bash
n = p * q
```

Como atacantes, si logramos factorizar `n`, podemos calcular la clave privada y romper la criptografía.

---

## Primeros Intentos

Probamos con el sitio web:

- [http://factordb.com/](http://factordb.com/)
    

Pero el número era demasiado grande, y no obtenemos resultados.

También intentamos herramientas como `sympy` en Python:

```python
>>> from sympy.ntheory import factorint
>>> factorint(RSA)
```

Esto funciona, pero para `n` muy grandes, puede tardar demasiado (horas o días).

---
# Ejemplo:
## Mejor Alternativa: SageMath

Para estos casos, la herramienta más eficiente y recomendada es **SageMath**, que permite factorizar con mejor rendimiento. Creamos un script en Python que recibe una clave RSA pública y extrae los valores primos:

```python
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from sage.all import *
from pwn import *

f = open("public.key", "r")
key = RSA.importKey(f.read())

e = key.e
n = key.n

p, q = factor(n)
p = int(p[0])
q = int(q[0])

log.info(f"e: {e}")
log.info(f"n: {n}")
log.info(f"p: {p}")
log.info(f"q: {q}")

m = n - (p + q - 1)
log.info(f"m: {m}")

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b//a) * y, y)

def modinv(a,m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

d = modinv(e, m)
log.info(f"d: {d}")

privateKey = RSA.construct((n, e, d, p, q))

print(f"\n\n[+] Listando la clave privada:\n\n")
print(privateKey.exportKey().decode())
```

---
# Solución:
## Explotación Automática

Para automatizar el reto, generamos un script `exploitation.py` que se conecta al servidor y responde con los factores correctos:

```python
#!/usr/bin/python3

from pwn import *
from Crypto.PublicKey import RSA
from sage.all import *

def solveChallenge():
	for _ in range(5):
		print(connection.recvline().decode().split()[2])
		connection.recvuntil(b"?\n")
		key = RSA.importKey(connection.recvuntil(b"-----END PUBLIC KEY-----\n").decode())

		p, q = factor(key.n)
		p = int(p[0])
		q = int(p[0])

		connection.sendlineafter(b"pumpkin = ", str(p).encode())
		connection.sendlineafter(b"pumpkin = ", str(q).encode())

		connection.recvline()

	print(f"\n\n[+] Mostrando la flag:\n\n")
	flag = connection.recvline().decode()
	print(flag)

if __name__ == '__main__':
	connection = remote("IP.Victima", <Puerto>)
	solveChallenge()
```

---

## Conclusión

Este reto fue un gran ejemplo de cómo la factorización de `n` puede comprometer un sistema RSA mal implementado. Aprendimos a usar herramientas como SageMath para resolver estos problemas de forma efectiva.

> Sin duda, un reto desafiante que te rompe la cabeza pero te deja afilado como atacante ❤️

---

**@sk8ware - GitHub | Ethical Hacking Enthusiast**