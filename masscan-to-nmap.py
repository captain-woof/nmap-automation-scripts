import xml.etree.ElementTree as ET
from argparse import ArgumentParser

 
parser = ArgumentParser()
parser.add_argument("-m", "--masscan-xml", action="store", help="Masscan XML output")
parser.add_argument("-o", "--out-dir", action="store", help="Nmap output directory for each target scan; default: './nmap/'", default="nmap")
args = parser.parse_args()

 
masscanXmlFilePath = args.masscan_xml
nmapOutDir = args.out_dir

 
# Take XML as input
tree = ET.parse(masscanXmlFilePath)
root = tree.getroot()

 
# Iterate over hosts and ports and prepare host -> ports mapping
hostToPortsMap = {}
hosts = root.findall("host")
for host in hosts:
    address = host.find("address").attrib["addr"]
    ports = set(map(lambda port: port.attrib["portid"], host.find("ports").findall("port")))

 
    if address in hostToPortsMap:
        hostToPortsMap[address].update(ports)

    else:
        hostToPortsMap[address] = ports

totalHosts = len(hostToPortsMap.keys())
print(f"Total {totalHosts} hosts found")


# Prepare nmap automation script
nmapCommand = ""
for addressIndex, address in enumerate(hostToPortsMap.keys()):
    # Status update
    if addressIndex % 5 == 0:
        scanPercentage = (addressIndex/totalHosts) * 100.0
        nmapCommand += f"echo '>>>> Scan {scanPercentage:.2f}% ({addressIndex}/{totalHosts}) complete'\n"

    # Command for this host
    ports = hostToPortsMap[address]
    nmapCommand += f"Scanning {address}"
    nmapCommand += f"nmap -T4 -Pn -sS -sV --version-intensity 3 --max-retries 3 -oX {nmapOutDir}/{address}.xml -p T:{",".join(ports)} {address}\n" # MODIFY THIS IF NEEDED

nmapFileName = "start_nmap.sh"
with open(nmapFileName, "w") as nmapFile:
    nmapFile.write("#!/bin/bash\n")
    nmapFile.write(nmapCommand + "\n")
    print(f"Nmap script written to '{nmapFileName}'")

 
# Prepare host->ports mapping list
listFileName = "host_and_ports.list"
with open(listFileName, "w") as listFile:
    for address, ports in hostToPortsMap.items():
        listFile.write(f"{address}:{",".join(ports)}\n")
    print(f"Host->Ports list written to '{listFileName}'")