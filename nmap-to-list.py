import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from glob import glob
from os import path

# HELPER
def sanitiseForCsv(text: str):
    # Check if the value needs to be quoted
    if any(char in text for char in ['"', ',', '\n', '\r']):
        # Escape double quotes by replacing them with two double quotes
        text = text.replace('"', '""')
        # Enclose the value in double quotes
        return f'"{text}"'
    return text

# MAIN
parser = ArgumentParser()
parserNmapXml = parser.add_mutually_exclusive_group(required=True)
parserNmapXml.add_argument("-n", "--nmap-xml", action="store", help="Nmap XML file")
parserNmapXml.add_argument("-nd", "--nmap-xml-dir", action="store", help="Directory containing multiple nmap XMLs")
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
nmapXmlDirPath = args.nmap_xml_dir

# Prepare XML file paths
nmapXmlFilePaths = []
if nmapXmlFilePath not in [None, ""]:
    nmapXmlFilePaths.append(nmapXmlFilePath)
elif nmapXmlDirPath not in [None, ""]:
    nmapXmlFilePaths.extend(glob(path.join(nmapXmlDirPath, '*.xml')))
else:
    print("At least one of `-n` or `-nd` required. Use `--help` to check usage.")
    exit(0)

# Results store
hostToPort = [] # HOST:PORT
hostToPortWeb = [] # HOST:PORT
webUrls = [] # https://HOST:PORT
csvContents = ["ip,port,service_type,service_name,device_type,tls_subject,http_title,system_info,notes"]

# Iterate over source XMLs
for nmapXmlFilePath in nmapXmlFilePaths:
    tree = ET.parse(nmapXmlFilePath)
    root = tree.getroot()
    hosts = root.findall("host")

    # Iterate over hosts
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
            scriptSystemInfo = ""

            scriptElements = portElement.findall("script")
            for scriptElement in scriptElements:
                scriptOutput = scriptElement.get("output", "")

                if scriptElement is not None:
                    # TLS/SSL certificate
                    if scriptElement.get("id", "").lower() == "ssl-cert":
                        scriptTlsSubject = scriptOutput

                    # HTTP title
                    elif scriptElement.get("id", "").lower() == "http-title":
                        scriptHttpTitle = scriptOutput

                    # System information
                    else:
                        systemInfoScriptNames = [
                            "http-ntlm-info",
                            "imap-ntlm-info",
                            "ms-sql-ntlm-info",
                            "nntp-ntlm-info",
                            "pop3-ntlm-info",
                            "rdp-ntlm-info",
                            "smtp-ntlm-info",
                            "telnet-ntlm-info",
                            "smb-system-info"
                        ]
                        for scriptName in systemInfoScriptNames:
                            if scriptElement.get("id", "").lower() == scriptName:
                                scriptSystemInfo += f"{scriptName}:\n{scriptOutput}\n"

            # Store results

            ## Web host -> web port mapping (https)
            if "https" in serviceName.lower():
                webUrls.append(f"https://{address}:{port}")
                hostToPortWeb.append(f"{address}:{port}")

            ## Web host -> web port mapping (http)
            elif "http" in serviceName.lower():
                webUrls.append(f"http://{address}:{port}")
                hostToPortWeb.append(f"{address}:{port}")

            ## CSV
            csvContents.append(f"{sanitiseForCsv(address)},{sanitiseForCsv(port)},{sanitiseForCsv(serviceName)},{" ".join([sanitiseForCsv(serviceProduct),sanitiseForCsv(serviceVersion),sanitiseForCsv(serviceExtraInfo)])},{sanitiseForCsv(serviceDeviceType)},{sanitiseForCsv(scriptTlsSubject)},{sanitiseForCsv(scriptHttpTitle)},{sanitiseForCsv(scriptSystemInfo)},todo")

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
