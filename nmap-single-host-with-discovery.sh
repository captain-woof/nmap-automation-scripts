#!/usr/bin/bash

# Display help
if [[ $1 == "-h" || $1 == "" ]]; then
    echo "Usage: ${0} <HOST>";
    exit;
fi

# Init - customisable
HOST=${1}
NUM_TOP_PORTS_TCP=1000
NUM_TOP_PORTS_UDP=100
DIR_NAME_RESULTS="nmap"
SCAN_SPEED="T4"

# Init - derived
DIR_RESULTS="${PWD}/${DIR_NAME_RESULTS}"
FILE_RESULTS_TCP_TOP="${DIR_RESULTS}/tcp_top_${NUM_TOP_PORTS_TCP}"
FILE_RESULTS_UDP_TOP="${DIR_RESULTS}/udp_top_${NUM_TOP_PORTS_UDP}"
FILE_RESULTS_TCP_TOP_DETAILED="${DIR_RESULTS}/tcp_top_${NUM_TOP_PORTS_TCP}_detailed"
FILE_RESULTS_UDP_TOP_DETAILED="${DIR_RESULTS}/udp_top_${NUM_TOP_PORTS_UDP}_detailed"
FILE_RESULTS_TCP_ALL="${DIR_RESULTS}/tcp_all"
FILE_RESULTS_UDP_ALL="${DIR_RESULTS}/udp_all"
FILE_RESULTS_TCP_ALL_DETAILED="${DIR_RESULTS}/tcp_all_detailed"
FILE_RESULTS_UDP_ALL_DETAILED="${DIR_RESULTS}/udp_all_detailed"

# START
echo ">>>> STARTING SCAN FOR ${HOST}"

# Make directory for results
if [[ -e ${DIR_RESULTS} ]]; then
    rm -rf ${DIR_RESULTS}
fi
mkdir -p ${DIR_RESULTS}

# Do top TCP ports
echo ">>>> SCANNING TOP ${NUM_TOP_PORTS_TCP} TCP ports"
sudo nmap -${SCAN_SPEED} -sS --source-port 53 --top-ports ${NUM_TOP_PORTS_TCP} -v -oA "${FILE_RESULTS_TCP_TOP}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
PORTS_TCP_TOP=$(cat "${FILE_RESULTS_TCP_TOP}.nmap" | grep "/tcp " | tr -s " " | cut -d " " -f 1 | cut -d "/" -f 1 | xargs --replace echo -ne {},)
sudo nmap -${SCAN_SPEED} -sS --source-port 53 -p ${PORTS_TCP_TOP:0:-1} -sC -sV -O -v -oA "${FILE_RESULTS_TCP_TOP_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"

# Do top UDP ports
echo ">>>> SCANNING TOP ${NUM_TOP_PORTS_UDP} UDP ports"
sudo nmap -${SCAN_SPEED} -sU --source-port 53 --top-ports ${NUM_TOP_PORTS_UDP} -v -oA "${FILE_RESULTS_UDP_TOP}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
PORTS_UDP_TOP=$(cat "${FILE_RESULTS_UDP_TOP}.nmap" | grep "/udp " | tr -s " " | cut -d " " -f 1 | cut -d "/" -f 1 | xargs --replace echo -ne {},)
sudo nmap -${SCAN_SPEED} -sU --source-port 53 -p ${PORTS_UDP_TOP:0:-1} -sC -sV -v -oA "${FILE_RESULTS_UDP_TOP_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"

# Do all TCP ports
echo ">>>> SCANNING ALL TCP ports"
sudo nmap -${SCAN_SPEED} -sS --source-port 53 -p- -v -oA "${FILE_RESULTS_TCP_ALL}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
PORTS_TCP_ALL=$(cat "${FILE_RESULTS_TCP_ALL}.nmap" | grep "/tcp " | tr -s " " | cut -d " " -f 1 | cut -d "/" -f 1 | xargs --replace echo -ne {},)
sudo nmap -${SCAN_SPEED} -sS --source-port 53 -p ${PORTS_TCP_ALL:0:-1} -sC -sV -v -oA "${FILE_RESULTS_TCP_ALL_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"

# Do all UDP ports
echo ">>>> SCANNING ALL UDP ports"
sudo nmap -${SCAN_SPEED} -sU --source-port 53 -p- -v -oA "${FILE_RESULTS_UDP_ALL}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
PORTS_UDP_ALL=$(cat "${FILE_RESULTS_UDP_ALL}.nmap" | grep "/udp " | tr -s " " | cut -d " " -f 1 | cut -d "/" -f 1 | xargs --replace echo -ne {},)
sudo nmap -${SCAN_SPEED} -sU --source-port 53 -p ${PORTS_UDP_ALL:0:-1} -sC -sV -v -oA "${FILE_RESULTS_UDP_ALL_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
