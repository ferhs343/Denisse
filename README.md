# Denisse

CONTINUA EN DESARROLLO ...........

  
```
                  /^----^\          Whoo!!
                  | 0  0 |
    Whoo!!        |  \/  |       Whoo!!
                  /       \
      Whoo!!     |     |;;;|
                 |     |;;;|          \   \
                 |      \;;|           \//
                  \       \|           / /
  -----------------(((--(((------------\ \--------------------------
  ------------------------------------------------------------------
```

Denisse se desarrolló con el objetivo de inspeccionar y analizar profundamente capturas de tráfico en busca del enemigo oculto, sin importar el tamaño ni complejidad del archivo PCAP. Su capacidad para procesar grandes volúmenes de datos de manera eficiente la convierte en una herramienta clave para identificar comportamientos anómalos y posibles intrusiones. Actualmente analiza diversos patrones para identificar diversos TTP, tales como: 

  - Examina el flujo a nivel TCP/UDP en busca de escaneos de puertos (Syn, Ack, Fin, Xmas, Maimon, etc), reverse shell, comunicaciones hacia posibles servidores C2, etc.
  - Examina el tráfico DNS en busca de consultas a dominios maliciosos, tunelizado DNS, etc.
  - Examina el tráfico HTTP en busca de descarga de artefactos sospechosos/maliciosos, webshells, etc.
  - Analiza posibles ataques de fuerza bruta mediante la examinación de tráfico SSH, FTP, etc.
  - Examina el tráfico de servicios de Microsoft (SMB2, Kerberos, NTLM, etc) en busca de movimientos laterales, ataques de autenticación, etc.

**Únicamente es compatible con sistemas basados en Debian.**

## Uso

Denisse requiere de 3 componentes clave para su funcionamiento, se tiene integrado un instalador para descargar las mismas.

  - `Tshark`
  - `Mergecap`
  - `PcapPlusPlus`

Denisse se ejecuta de la siguiente manera (como usuario root):

  bash ./Denisse.sh [OPCIONES]

Las opciones disponibles son las siguientes:

  - `-h | --help`: Muestra el panel de ayuda.
  - `-p | --protocols`: Especifica los protocolos (separados por coma) en los cuales Denisse llevará a cabo su análisis. Los protocolos soportados son: `tcp`, `udp`, `http`, `dns`, `smb2`, `rpc`, `dcerpc`, `ntlm`, `kerberos`, `ftp`, `ssh`.
  - `-a | --all`: Al especificar este parámetro, Denisse realizará su análisis en todos los protocolos soportados.

  Ejemplos:

      bash ./Denisse.sh -p tcp,http
      bash ./Denisse.sh -a
      bash ./Denisse.sh -h

Una vez especificado los parametros necesarios, Denisse está listo para cazar al enemigo oculto en tu infraestructura, lo único que se tendrá que hacer es proporcionarle un archivo PCAP, este lo recortará en archivos más pequeños dependiendo de la longitud del mismo, con el objetivo de llevar a cabo un análisis eficiente y no saturar el uso de memoria.

**NOTA:** Todos los pcap a analizar deberán guardarse en la carpeta "Pcaps", de lo contrario, no se leeran los mismos.

<div align="center">
<img width="545" alt="image" src="https://github.com/user-attachments/assets/40341ce5-50d1-4952-9ec4-d6147363f9a4" />
</div>

Tras unos pocos minutos de análisis, Denisse alertará sobre los hallazgos detectados (Sí existen). Además, los flujos de actividad sospechosa serán extraídos en archivos PCAP y registros en formato JSON que contiene todos los datos relevantes del tráfico de red.

**Ejemplo de salida JSON para detecciones TCP.**
```
{
  "sessionId": 990,
  "timestamp": "Apr-11,-2025-22:58:26.312539000-CST",
  "sourceIp": "192.168.1.106",
  "destIp": "192.168.1.254",
  "portSrc": "56067",
  "portImpacted": 988,
  "flagsHistory": "Fin",
  "packets": 1,
  "bytes": 0,
  "connStatus": "Fin-only"
}
{
  "sessionId": 991,
  "timestamp": "Apr-11,-2025-22:58:28.066969000-CST",
  "sourceIp": "192.168.1.106",
  "destIp": "192.168.1.254",
  "portSrc": "56067",
  "portImpacted": 996,
  "flagsHistory": "Fin",
  "packets": 1,
  "bytes": 0,
  "connStatus": "Fin-only"
}
```
