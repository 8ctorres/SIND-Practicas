import shodan
from urllib.parse import quote_plus

if __name__ == "__main__":
    # Read Shodan API Key from a file named "shodan.key" in the same directory as this script
    with open("shodan.key") as keyfile:
        api_key = keyfile.readline()

    # The three search queries I was given for this assignment were the following:
    queries = [
        'webcam 7 -401',
        'Netbotz Appliance',
        'vsftpd 2.3.4 -port:21 -ip:189.145.217.20'
    ]
    # Conectámonos á API de Shodan
    shodan_api = shodan.Shodan(api_key)
    # Conectámonos á API de Exploits
    exploits_api = shodan.Shodan.Exploits(shodan_api)
    # Para optimizar o uso da API e evitar facer moitas chamadas, primeiro facemos todas as buscas
    # e despois mostramos os resultados
    # Gardamos os resultados nunha lista (un resultado por consulta). Á súa vez cada resultado é unha lista
    results = list()
    # Gardamos os hosts nun dicionario indexado por IP
    hosts = dict()
    # Gardamos os exploits nun dicionario indexado por código de CVE
    exploits = dict()
    # En primeiro lugar, facemos as tres consultas de busca
    for query in queries:
        print("Querying Shodan API... ", query)
        api_res = shodan_api.search(quote_plus(query), limit=5, minify=True)
        if api_res['total'] > 0:
            results.append(api_res['matches'])
    # Percorremos a lista de resultados e facemos unha consulta de host para cada un dos hosts
    for result in results:
        for device in result:
            # Sacamos a IP
            ip = device['ip_str']
            # Facemos a consulta por IP
            print("Querying Shodan Host API... ", ip)
            host_result = shodan_api.host(ip, history=False, minify=True)
            # Gardamos o resultado no dicionario de hosts
            hosts[ip] = host_result
            # Se hai vulnerabilidades, primeiro comprobamos si xa temos esa información cacheada
            # Se non, facemos unha petición á API de Exploits para cada unha de elas
            try:
                for vuln in host_result['vulns']:
                    if exploits.get(vuln.upper()) is None:
                        # Non atopamos a vulnerabilidade en local, buscamos na API
                        print("Querying Shodan Exploits API... ", vuln)
                        vuln_result = exploits_api.search(vuln)
                        if vuln_result['total'] > 0:
                            # Gardamos o resultado no dicionario
                            exploits[vuln.upper()] = vuln_result['matches']
            except KeyError:
                # Non hai vulnerabilidades, non facemos nada
                pass

    # Mostramos a información obtida
    for i in range(3):
        print()
        print("-"*50)
        print("-"*50)
        print(f"Busca: {queries[1]}")
        # Mostramos a información desexada para cada un dos 20 resultados que obtemos
        print("Resultados obtidos")
        for device in results[i]:
            print()
            print("-"*50)
            # Eliminar caracteres CR e separar por liñas
            service_data = device['data'].replace("\r\n", "\n").split("\n")
            print(f"Resposta do servicio:")
            for line in service_data:
                if line == "":
                    print()
                    break
                elif len(line)>80:
                    print("\t", line[:80], "...[TRUNCATED]")
                else:
                    print("\t", line)
            print(f"Organización á que pertence: {device['org']}")
            print(f"Ubicación do dispositivo: {device['location']['city']}, {device['location']['country_name']}")
            # Para averiguar os portos e vulnerabilidades detectados, miramos no dicionario de hosts
            host_info = hosts[device['ip_str']]
            ports = host_info['ports']
            ports.sort()
            print(f"Portos detectados por Shodan:")
            for port in ports:
                print("\t", port)
            # Mostramos as vulnerabilidades detectadas
            print("Vulnerabilidades detectadas automáticamente por Shodan:")
            try:
                vulns = host_info['vulns']
                vulns.sort()
                for vuln in vulns:
                    print("\t", vuln, end='')
                    # Para cada vulnerabilidade, miramos no dicionario de exploits por si podemos mostrar algo
                    try:
                        this_exploit = exploits[vuln.upper()]
                        # Buscamos por algún resultado de ExploitDB
                        found = False
                        for entry in this_exploit:
                            if entry['source'] == "ExploitDB":
                                found = True
                                print(" -> ", entry['description'], " - ExploitDB Entry ", entry['_id'])
                        if not found:
                            # Se non atopamos nada, pasamos á seguinte liña sen máis
                            print()
                    except KeyError:
                        # Non hai exploits para ese CVE
                        # Saltamos liña e seguimos
                        print()
            except KeyError:
                print("\tNingunha")
