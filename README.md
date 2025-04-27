# Denisse

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

Denisse se desarrolló con el objetivo de encontrar al enemigo oculto en tu red, mediante un análisis profundo de capturas de tráfico, sin importar su tamaño ni complejidad. Su capacidad para procesar grandes volúmenes de datos de manera eficiente la convierte en una herramienta clave para identificar comportamientos anómalos y posibles intrusiones. Actualmente analiza diversos patrones, tales como: 

  - Examina el flujo a nivel TCP/UDP en busca de escaneos de puertos (Syn, Ack, Fin, Xmas, Maimon, etc), reverse shell, comunicaciones hacia posibles servidores C2, etc.
  - Examina el tráfico DNS en busca de consultas a dominios maliciosos, tunelizado DNS, etc.
  - Examina el tráfico HTTP en busca de descarga de artefactos sospechosos/maliciosos, webshells, etc.
  - Analiza posibles ataques de fuerza bruta mediante la examinación de tráfico SSH, FTP, etc.
  - Examina el tráfico de servicios de Microsoft (SMB2, Kerberos, NTLM, etc) en busca de movimientos laterales, ataques de autenticación, etc.

**Únicamente es compatible con sistemas basados en Debian.**

## Como utilizar?

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

<img width="545" alt="image" src="https://github.com/user-attachments/assets/40341ce5-50d1-4952-9ec4-d6147363f9a4" />

Tras unos pocos minutos de análisis, Denisse alertará sobre los hallazgos detectados (Sí hay). Además, los flujos de actividad sospechosa serán extraídos en archivos PCAP y registros en formato JSON que contiene todos los datos relevantes del tráfico de red.

<img width="712" alt="image" src="https://github.com/user-attachments/assets/f25afa37-8914-43b3-b051-bade4eb55acf" />


<img width="1258" alt="image" src="https://github.com/user-attachments/assets/3420f8e8-5a98-4458-b7d4-9c4ac5930afe" />


## IMPORTANTE: Dato a tener en cuenta

Como se mencionó anteriormente, Denisse utiliza **`PcapPlusPlus`**, este es una librería de C++ de código abierto diseñada para capturar, analizar y manipular tráfico de red. Denisse lo implementa para recortar archivos PCAP dependiendo de su tamaño, con el objetivo de tener un rendimiento y uso de memoria eficaz al manipular el mismo. Sin embargo, es posible que al momento de que Denisse realice el recorte del archivo Pcap mediante PcapPlusPlus se obtenga el siguiente error:

<img width="533" alt="image" src="https://github.com/user-attachments/assets/bc70a425-3d03-4449-9f70-0aa5fd7fcaf7" />

Al momento de la publicación de Denisse se desconoce si este error ocurre en todos los equipos, sin embargo, sí experimentas de manera persistente este error, sigue los siguientes pasos para dar solución a este error:

  - Al interior de la carpeta de este proyecto, abre con cualquier editor de texto (nano, vim, etc) el siguente archivo: PcapPlusPlus/Pcap++/src/PcapFileDevice.cpp
<img width="367" alt="image" src="https://github.com/user-attachments/assets/9a715d65-68ef-45e7-8c23-6951fd5dd845" />

  - Localiza la función **`bool PcapFileWriterDevice::open`**
<img width="919" alt="image" src="https://github.com/user-attachments/assets/e1da12ab-33d8-43aa-9d4c-120495544efe" />

  - Reemplaza el contenido de la función con el código que se encuentra en el archivo **`PcapPlusPlus_error_solution`** dentro del repositorio de Denisse.
  - Dirígete a la ruta **`PcapPlusPlus/build/`** y ejecuta los siguientes comandos para compilar nuevamente:
      - `cmake ..`
      - `make install`

