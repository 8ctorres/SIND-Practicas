# SIND-Practicas

Seguridad en Entornos Industriales - Máster Universitario en Ciberseguridade - Universidade da Coruña

## Shodan

O obxectivo desta práctica é familiarizarse co motor de buscas Shodan. A primeira parte da práctica consiste en manualmente buscar tres tipos de dispositivos asignados polo profesor de prácticas. A segunda parte consiste en desenvolver un pequeno programa ou script que automatice esa tarefa e mostre por pantalla os resultados.

## Uso do script

Este é un sinxelo script en Python no cal as buscas están xa incluídas no propio script, ainda que se poden modificar sin ningún problema. Por defecto mostra 20 resultados de cada busca, aínda que tamén se pode cambiar fácilmente.

O único requisito é ter instalada a librería de Shodan para Python, e ter un arquivo chamado `shodan.key` no mismo directorio, que conteña a nosa clave para consultar a API de Shodan. Por motivos de privacidade, a miña clave non está incluída no repositorio.

O script execútase con `python3 sind.py` e mostra por pantalla toda a información que se pide na práctica.

## Exemplo de saída

A continuación móstrase un pequeno fragmento da saída obtida nunha execución cos valores por defecto (as tres buscas da práctica, e 20 resultados por busca).

A saída completa do script está dispoñible no ficheiro [output.txt](output.txt).

```
--------------------------------------------------
--------------------------------------------------
Busca asignada: Netbotz Appliance
Resultados obtidos

--------------------------------------------------
Resposta do servicio:
	 HTTP/1.1 401 Unauthorized
	 Server: thttpd/2.25b 29dec2003
	 WWW-Authenticate: Basic realm="NetBotz Appliance"
	 Transfer-Encoding: chunked
	 Connection: close
	 Expires: Sat, 01 Jan 2000 12:00:00 GMT

Organización á que pertence: Instituto Latinoamericano de la Comunicacion Educa
Ubicación do dispositivo: Mexico City, Mexico
Portos detectados por Shodan:
	 443
	 1723
Vulnerabilidades detectadas automáticamente por Shodan:
	 CVE-2015-0204

--------------------------------------------------
Resposta do servicio:
	 HTTP/1.1 401 Unauthorized
	 Server: thttpd/2.25b 29dec2003
	 WWW-Authenticate: Basic realm="NetBotz Appliance"
	 Transfer-Encoding: chunked
	 Connection: close
	 Expires: Sat, 01 Jan 2000 12:00:00 GMT

Organización á que pertence: University of Utah
Ubicación do dispositivo: Salt Lake City, United States
Portos detectados por Shodan:
	 80
	 443
Vulnerabilidades detectadas automáticamente por Shodan:
	 CVE-2015-0204

--------------------------------------------------
--------------------------------------------------
Busca asignada: vsftpd 2.3.4 -port:21 -ip:189.145.217.20
Resultados obtidos

--------------------------------------------------
Resposta do servicio:
	 220 (vsFTPd 2.3.4)
	 230 Login successful.
	 214-The following commands are recognized.
	  ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD
	  MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR
	  RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD
	  XPWD XRMD
	 214 Help OK.
	 211-Features:
	  EPRT
	  EPSV
	  MDTM
	  PASV
	  REST STREAM
	  SIZE
	  TVFS
	  UTF8
	 211 End

Organización á que pertence: OC1-HostForWeb, LLC
Ubicación do dispositivo: Buffalo, United States
Portos detectados por Shodan:
	 21
	 25
	 53
	 80
	 993
	 995
	 3306
Vulnerabilidades detectadas automáticamente por Shodan:
	 CVE-2006-20001
	 CVE-2008-0455
	 CVE-2011-0419
	 CVE-2011-3192
	 CVE-2011-3348
	 CVE-2011-3639
	 CVE-2012-0021
	 CVE-2012-0031
	 CVE-2012-0053
	 CVE-2012-0883
	 CVE-2012-2687
	 CVE-2012-3499
	 CVE-2012-4557
	 CVE-2012-4558
	 CVE-2013-1862
	 CVE-2013-1896
	 CVE-2013-5704
	 CVE-2013-6438
	 CVE-2014-0098
	 CVE-2014-0118
	 CVE-2014-0226
	 CVE-2014-0231
	 CVE-2015-0204
	 CVE-2015-0228
	 CVE-2015-3183
	 CVE-2015-4000
	 CVE-2016-4975
	 CVE-2016-5387
	 CVE-2016-8612
	 CVE-2016-8743
	 CVE-2017-3167
	 CVE-2017-3169
	 CVE-2017-7679
	 CVE-2017-9788
	 CVE-2017-9798
	 CVE-2018-1301
	 CVE-2018-1302
	 CVE-2018-1303
	 CVE-2021-34798
	 CVE-2021-39275
	 CVE-2021-40438
	 CVE-2021-44790
	 CVE-2022-22719
	 CVE-2022-22720
	 CVE-2022-22721
	 CVE-2022-28330
	 CVE-2022-28614
	 CVE-2022-28615
	 CVE-2022-29404
	 CVE-2022-30556
	 CVE-2022-31813
	 CVE-2022-37436
```
