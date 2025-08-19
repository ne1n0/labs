#  Laboratorio de Ataque en Cadena con Splunk Enterprise

---

##  Introducción  

Este laboratorio tiene como propósito **simular un ataque en cadena dentro de un entorno controlado**, utilizando **Splunk Enterprise** como plataforma central de monitoreo y análisis de seguridad.  

El laboratorio reproduce, paso a paso, distintas fases reales de un ataque cibernético, simulando el comportamiento de un adversario en un entorno corporativo. Cada fase genera eventos de seguridad en los sistemas comprometidos, los cuales son enviados a Splunk mediante **Universal Forwarder**, permitiendo su detección, correlación y análisis.  

El flujo general del laboratorio está inspirado en el modelo de la **Cyber Kill Chain** y técnicas de **MITRE ATT&CK**, siguiendo este orden:  

| Fase | Técnica simulada           | Eventos generados       | MITRE     |
| ---- | -------------------------- | ----------------------- | --------- |
| 1    | Fuerza bruta RDP           | 4625, 4740              | T1110.001 |
| 2    | Reconocimiento post-acceso | 4688                    | T1059     |
| 3    | Descarga de malware        | 4688 + conexión externa | T1105     |
| 4    | Persistencia               | 4657 / 4688             | T1547     |

##  Infraestructura del Laboratorio  

| Componente             | Dirección IP       | Rol                                                |
|------------------------|--------------------|-----------------------------------------------------|
| **Windows Server 2022** | 192.168.100.128     | Servidor Splunk Enterprise (SIEM)                   |
| **Windows 10**          | 192.168.100.120     | Endpoint víctima con Universal Forwarder            |
| **Kali Linux**          | 192.168.100.110     | Máquina atacante que ejecuta las distintas fases    |

## Escenarios de Ataque 

1. **Fuerza bruta RDP**  
   - Desde Kali Linux se realizan múltiples intentos fallidos de inicio de sesión RDP hacia el Windows 10.  
   - El Windows 10 genera eventos 4625 (logon failed).  
   - Splunk recolecta los logs vía Forwarder y se ejecuta una búsqueda para identificar 5 o más intentos fallidos desde la misma IP.  

2. **Ejecución de comandos maliciosos tras acceso**  
   - Una vez obtenido acceso válido, el atacante ejecuta comandos de reconocimiento en el endpoint.  
   - Se generan eventos 4688 (process creation).  
   - Splunk permite detectar procesos sospechosos como `whoami`, `ipconfig`, `net user`, etc.  

3. **Descarga de malware simulado**  
   - El atacante descarga un archivo desde internet usando `certutil` o `powershell Invoke-WebRequest`.  
   - Estos procesos quedan registrados en logs de seguridad.  
   - Splunk los identifica por la combinación de procesos inusuales con conexiones de red salientes.  

4. **Persistencia**  
   - Se crea una clave en el registro de Windows para ejecutar un binario al iniciar sesión.  
   - Eventos 4657 (Registry value modification) o 4688 (nuevo proceso en startup) son generados.  
   - En Splunk se correlacionan para identificar cambios en persistencia.  


#  Escenario 1: Fuerza bruta RDP

---

##  Objetivo del Escenario

Simular un ataque de fuerza bruta contra el servicio de **Escritorio Remoto (RDP)** en una máquina con Windows 10, utilizando la herramienta **Hydra** desde Kali Linux. El propósito es **generar múltiples intentos fallidos de inicio de sesión** que queden registrados en los eventos de seguridad del sistema y sean posteriormente **detectados y analizados mediante Splunk Enterprise**.

Este escenario representa la **fase de reconocimiento y acceso inicial** dentro de la cadena de ataque, permitiendo validar la capacidad del SIEM para identificar comportamientos anómalos desde una misma fuente.

---

##  Componentes Involucrados

| Rol                | Detalles                                        |
|-------------------|-------------------------------------------------|
| Máquina víctima    | Windows 10 con RDP habilitado                  |
| Máquina atacante   | Kali Linux ejecutando ataque con Hydra         |
| Recolector SIEM    | Splunk Enterprise en Windows Server 2022       |
| Agente de envío    | Universal Forwarder en Windows 10              |

---


##  Ejecución del Ataque

Se realizaron dos variantes del ataque de fuerza bruta desde Kali Linux, utilizando `Hydra`. Cada una representa un enfoque diferente utilizado por atacantes reales.

---

###  Variante 1: Ataque a un usuario específico conocido

En esta variante, se asume que el atacante ya conoce un nombre de usuario válido. Usando Hydra, lanza un ataque de fuerza bruta dirigido exclusivamente a esa cuenta, probando múltiples contraseñas extraídas del diccionario rockyou.txt.

```bash
sudo hydra -t 1 -V -f -l Usuario -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.120
```
![Ataque hydra to Usuario](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/user-atk.png)

 - -l: Especifica el usuario en el ataque
 - -P : Especifica la dura donde se encuentra el diccionario de  a utilizazr.
 - -t: Especifica la cantidad de hilo a utilizar.
 - -V: Verbose
 - -f: Detiene el proceso cuando encuentra la contraseña correcta.

Cada intento fallido de autenticación genera un evento con ID 4625 en el visor de eventos de Windows, que luego es recolectado por el Universal Forwarder y enviado a Splunk.

Estos eventos incluyen detalles como:

| Campo                        | Valor                                                 |
| ---------------------------- | ----------------------------------------------------- |
| **EventCode**                | 4625 (Error al iniciar sesión)                        |
| **Usuario atacado**          | `Usuario`                                             |
| **Motivo del error**         | Nombre de usuario desconocido o contraseña incorrecta |
| **Estado**                   | `0xC000006D`                                          |
| **Subestado**                | `0xC000006A`                                          |
| **Equipo de origen**         | `kali`                                                |
| **Dirección IP de origen**   | `192.168.100.110`                                     |
| **Tipo de inicio de sesión** | 3 (red/servicio de red)                               |


A continuación, se muestra cómo aparece este evento en Splunk

![Eventos 4625 para Usuario](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/4625.png)

Tras múltiples intentos fallidos consecutivos (10 en este caso), Windows bloquea automáticamente la cuenta objetivo. Esto queda registrado con el evento 4740

| Campo                            | Valor                              |
| -------------------------------- | ---------------------------------- |
| **EventCode**                    | 4740 (Cuenta de usuario bloqueada) |
| **Cuenta bloqueada**             | `Usuario`                          |
| **Equipo origen del bloqueo**    | `kali`                             |
| **Nombre de la máquina víctima** | `DESKTOP-LGSII8V`                  |
| **Dominio**                      | WORKGROUP                          |


![Evento 4740 - Cuenta bloqueada](https://github.com/ne1n0/labs/blob/main/splunk-scan-detection/images/4740.png)