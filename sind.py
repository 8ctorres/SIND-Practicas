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
    # Repetimos o exercicio para cada unha das tres queries
    for query in queries:
        print()
        print("-"*50)
        print("-"*50)
        print(f"Busca asignada: {query}")
        results = shodan_api.search(quote_plus(query), limit=5, minify=True)
        # Mostramos a información desexada para cada un dos 20 resultados que obtemos
        print("Resultados obtidos")
        for device in results['matches']:
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
            # Para averiguar os portos e vulnerabilidades detectados, facemos unha consulta de tipo "host"
            host_info = shodan_api.host(device['ip_str'],history=False, minify=True)
            ports = host_info['ports']
            ports.sort()
            print(f"Portos detectados por Shodan:")
            for port in ports:
                print("\t", port)
            # Mostramos as vulnerabilidades detectadas automáticamente
            print("Vulnerabilidades detectadas automáticamente por Shodan:")
            try:
                vulns = host_info['vulns']
                vulns.sort()
                for vuln in vulns:
                    print("\t", vuln)
            except KeyError:
                print("\tNingunha")
