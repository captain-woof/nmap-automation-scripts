import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from glob import glob
from os import path, mkdir

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
parser.add_argument("-d", "--outdir", action="store", help="Output directory for result lists; default: 'nmap-lists'", default="nmap-lists")
parser.add_argument("--hosts-ips", action="store", help="Output file for HOST IPs; default: 'hosts_ips.txt'", default="hosts_ips.txt")
parser.add_argument("--hosts-names", action="store", help="Output file for HOST IPs and Names; default: 'hosts_names.txt'", default="hosts_names.txt")
parser.add_argument("--ip-to-port", action="store", help="Output file for IP:PORT; default: 'ip_to_port.txt'", default="ip_to_port.txt")
parser.add_argument("--hostname-to-port", action="store", help="Output file for HOSTNAME:PORT; default: 'hostname_to_port.txt'", default="hostname_to_port.txt")
parser.add_argument("--ip-to-port-web", action="store", help="Output file for IP:PORT (web); default: 'ip_to_port_web.txt'", default="ip_to_port_web.txt")
parser.add_argument("--hostname-to-port-web", action="store", help="Output file for HOSTNAME:PORT (web); default: 'hostname_to_port_web.txt'", default="hostname_to_port_web.txt")
parser.add_argument("--urls-base", action="store", help="Output file for http://HOST:PORT (containing both IPs and hostnames); default: 'urls_base.txt'", default="urls_base.txt")
parser.add_argument("--csv", action="store", help="Output file for CSV; default: 'nmap.csv'", default="nmap.csv")
args = parser.parse_args()

# Create output directory if needed
try:
    mkdir(args.outdir)
    print(f"Output directory '{args.outdir}' created")
except:
    pass

# Parse file paths
hostsIpsFileName = path.join(args.outdir, args.hosts_ips)
hostsNamesFileName = path.join(args.outdir, args.hosts_names)
hostnameToPortFileName = path.join(args.outdir, args.hostname_to_port)
ipToPortFileName = path.join(args.outdir, args.ip_to_port)
ipToPortWebFileName = path.join(args.outdir, args.ip_to_port_web)
hostnameToPortWebFileName = path.join(args.outdir, args.hostname_to_port_web)
webUrlsFileName = path.join(args.outdir, args.urls_base)
csvFilePathName = path.join(args.outdir, args.csv)
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
hostIpsSet = set() # Host IPs
hostnamesSet  = set() # Host Names
ipToPortSet = set() # IP:PORT
hostnameToPortSet = set() # HOST:PORT
ipToPortWebSet = set() # IP:PORT
hostnameToPortWebSet = set() # HOST:PORT
webUrlsSet = set() # https://HOST:PORT
csvContentsSet = set(["ip,hostname,port,service_type,service_name,device_type,tls_subject,http_title,system_info,notes"])

# Iterate over source XMLs
for nmapXmlFilePath in nmapXmlFilePaths:
    tree = ET.parse(nmapXmlFilePath)
    root = tree.getroot()
    hosts = root.findall("host")

    # Iterate over hosts
    for host in hosts:
        address = host.find("address").get("addr", "")
        hostnamesElementsRoot = host.find("hostnames")
        hostnames = []
        if hostnamesElementsRoot != None:
            hostnames.extend(map(lambda hostnameElement: hostnameElement.get("name"), hostnamesElementsRoot.findall("hostname")))
        
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

            ## Hosts (IPs and Names)
            hostIpsSet.add(address)
            hostnamesSet = hostnamesSet.union(hostnames)

            ## Web host -> web port mapping (http and https)
            if "http" in serviceName.lower() or scriptTlsSubject != "":
                ipToPortWebSet.add(f"{address}:{port}")
                for hostname in hostnames:
                    hostnameToPortWebSet.add(f"{hostname}:{port}")

            if "https" in serviceName.lower() or scriptTlsSubject != "":
                webUrlsSet.add(f"https://{address}:{port}")
                for hostname in hostnames:
                    webUrlsSet.add(f"https://{hostname}:{port}")

            elif "http" in serviceName.lower():
                webUrlsSet.add(f"http://{address}:{port}")
                for hostname in hostnames:
                    webUrlsSet.add(f"http://{hostname}:{port}")

            ## CSV
            csvContentsSet.add(f"{sanitiseForCsv(address)},{sanitiseForCsv('/'.join(hostnames))},{sanitiseForCsv(port)},{sanitiseForCsv(serviceName)},{' '.join([sanitiseForCsv(serviceProduct),sanitiseForCsv(serviceVersion),sanitiseForCsv(serviceExtraInfo)])},{sanitiseForCsv(serviceDeviceType)},{sanitiseForCsv(scriptTlsSubject)},{sanitiseForCsv(scriptHttpTitle)},{sanitiseForCsv(scriptSystemInfo)},todo")

            ## Generic host -> port mapping
            ipToPortSet.add(f"{address}:{port}")
            for hostname in hostnames:
                hostnameToPortSet.add(f"{hostname}:{port}")
            
# Output files
with open(hostsIpsFileName, "w") as fileToWrite:
    for lineToWrite in hostIpsSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOST IPs list written to '{hostsIpsFileName}'")

with open(hostsNamesFileName, "w") as fileToWrite:
    for lineToWrite in hostnamesSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOST Names list written to '{hostsNamesFileName}'")

with open(hostnameToPortFileName, "w") as fileToWrite:
    for lineToWrite in hostnameToPortSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOSTNAME:PORT list written to '{hostnameToPortFileName}'")

with open(ipToPortFileName, "w") as fileToWrite:
    for lineToWrite in ipToPortSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"IP:PORT list written to '{ipToPortFileName}'")

with open(hostnameToPortWebFileName, "w") as fileToWrite:
    for lineToWrite in hostnameToPortWebSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"HOSTNAME:PORT (web) list written to '{hostnameToPortWebFileName}'")

with open(ipToPortWebFileName, "w") as fileToWrite:
    for lineToWrite in ipToPortWebSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"IP:PORT (web) list written to '{ipToPortWebFileName}'")

with open(webUrlsFileName, "w") as fileToWrite:
    for lineToWrite in webUrlsSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"http://HOST:PORT list written to '{webUrlsFileName}'")

with open(csvFilePathName, "w") as fileToWrite:
    for lineToWrite in csvContentsSet:
        fileToWrite.write(lineToWrite + "\n")
    print(f"CSV written to '{csvFilePathName}'")
