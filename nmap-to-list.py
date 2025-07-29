import xml.etree.ElementTree as ET
from argparse import ArgumentParser

"""
README

For multiple nmap XMLs, do:

ls ./*.xml | xargs --replace={} python3 nmap-to-list.py -n {}
cat host_to_port.txt | sort | uniq > 1.txt
cat host_to_port_web.txt | sort | uniq > 2.txt
cat urls_base.txt | sort | uniq > 3.txt
mv 1.txt host_to_port.txt
mv 2.txt host_to_port_web.txt
mv 3.txt urls_base.txt
"""

parser = ArgumentParser()
parser.add_argument("-n", "--nmap-xml", action="store", help="Nmap XML")
parser.add_argument("--host-to-port", action="store", help="Output file for HOST:PORT; default: 'host_to_port.txt'", default="host_to_port.txt")
parser.add_argument("--host-to-port-web", action="store", help="Output file for HOST:PORT for web (http and https); default: 'host_to_port_web.txt'", default="host_to_port_web.txt")
parser.add_argument("--urls-base", action="store", help="Output file for http://HOST:PORT; default: 'urls_base.txt'", default="urls_base.txt")
parser.add_argument("--csv", action="store", help="Output file for CSV; default: 'nmap.csv'", default="nmap.csv")
args = parser.parse_args()

hostToPortFileName = args.host_to_port
hostToPortWebFileName = args.host_to_port_web
webUrlsFileName = args.urls_base
csvFilePath = args.csv
nmapXmlFilePath = args.nmap_xml

# Take XML as input
tree = ET.parse(nmapXmlFilePath)
root = tree.getroot()
hosts = root.findall("host")

# Iterate over hosts
hostToPort = [] # HOST:PORT
hostToPortWeb = [] # HOST:PORT
webUrls = [] # https://HOST:PORT
csvContents = ["ip,port,service_type,service_name,device_type,tls_subject,http_title,notes"]

for host in hosts:
    address = host.find("address").get("addr", "")
    if address == "":
        continue

    portsElementsRoot = host.find("ports")
    if portsElementsRoot is None:
        continue
    portsElements = portsElementsRoot.findall("port")
    if portsElements is None:
        continue

    for portElement in portsElements:
        port = portElement.get("portid", "")
        if port == "":
            continue

        # Process services
        serviceName = ""
        serviceProduct = ""
        serviceVersion = ""
        serviceExtraInfo = ""
        serviceDeviceType = ""

        serviceElement = portElement.find("service")
        if serviceElement is not None:
            serviceName = serviceElement.get("name", "")
            serviceProduct = serviceElement.get("product", "")
            serviceVersion = serviceElement.get("version", "")
            serviceExtraInfo = serviceElement.get("extrainfo", "")
            serviceDeviceType = serviceElement.get("devicetype", "")

        # Process scripts
        scriptTlsSubject = ""
        scriptHttpTitle = ""

        scriptElements = portElement.findall("script")
        for scriptElement in scriptElements:
            if scriptElement is not None:
                # TLS/SSL certificate
                if scriptElement.get("id", "").lower() == "ssl-cert":
                    scriptTlsSubject = scriptElement.get("output", "")

                # HTTP title
                elif scriptElement.get("id", "").lower() == "http-title":
                    scriptHttpTitle = scriptElement.get("output", "")

                # http-ntlm-info

        # Store results

        ## Web host -> web port mapping (https)
        if serviceName.lower() == "https":
            webUrls.append(f"https://{address}:{port}")
            hostToPortWeb.append(f"{address}:{port}")

        ## Web host -> web port mapping (http)
        elif serviceName.lower() == "http":
            webUrls.append(f"http://{address}:{port}")
            hostToPortWeb.append(f"{address}:{port}")

        ## CSV
        csvContents.append(f"{address},{port},{serviceName},{" ".join([serviceProduct,serviceVersion,serviceExtraInfo])},{serviceDeviceType},{scriptTlsSubject},{scriptHttpTitle},todo")

        ## Generic host -> port mapping
        hostToPort.append(f"{address}:{port}")
            

# Output files
with open(hostToPortFileName, "a") as fileToWrite:
    for lineToWrite in hostToPort:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOST:PORT list written to '{hostToPortFileName}'")

with open(hostToPortWebFileName, "a") as fileToWrite:
    for lineToWrite in hostToPortWeb:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOST:PORT (web) list written to '{hostToPortWebFileName}'")

with open(webUrlsFileName, "a") as fileToWrite:
    for lineToWrite in webUrls:
        fileToWrite.write(lineToWrite + "\n")
    print(f"http://HOST:PORT list written to '{webUrlsFileName}'")

with open(csvFilePath, "a") as fileToWrite:
    for lineToWrite in csvContents:
        fileToWrite.write(lineToWrite + "\n")
    print(f"CSV written to '{csvFilePath}'")
