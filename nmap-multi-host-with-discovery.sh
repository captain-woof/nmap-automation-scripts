#!/usr/bin/bash

# Display help
if [[ $1 == "-h" || $1 == "" ]]; then
    echo "Usage: ${0} <HOST1> <HOST2>... [OUT_OF_SCOPE_1,OUT_OF_SCOPE_2,...]";
    exit;
fi

# Common init - customisable
DIR_NAME_RESULTS="nmap"

# Common init - derived
DIR_RESULTS="${PWD}/${DIR_NAME_RESULTS}"
OUT_OF_SCOPE=${2}
OUT_OF_SCOPE_ARG=""

# Out of scope argument
if [[ -n ${OUT_OF_SCOPE} ]]; then
    OUT_OF_SCOPE_ARG="--exclude ${OUT_OF_SCOPE}"
fi

# Make directory for results
if [[ -e ${DIR_RESULTS} ]]; then
    echo "Output directory ${DIR_RESULTS} already exists. Continuing will overwrite data. Exiting."
    exit
else
    echo "Creating new directory for results: ${DIR_RESULTS}"
    mkdir -p ${DIR_RESULTS}
fi

# Function - Host discovery
function host_discovery() {
    # Init - customisable
    HOSTS=${1}
    SCAN_SPEED="T4"
    MIN_HOSTGROUP="50"

    # Init - derived
    FILE_RESULTS_AVAILABLE_HOSTS="${DIR_RESULTS}/available_hosts"

    # Start hosts discovery
    echo ">>>> STARTING HOSTS DISCOVERY IN ${HOSTS}"
    sudo nmap ${OUT_OF_SCOPE_ARG} -n --min-hostgroup ${MIN_HOSTGROUP} -${SCAN_SPEED} -sn -PS80,8080,8000,443,445,137,139,138,25,587,143,993,110,995,22,21,5985,53,88,2049,111,3389,23 -PU123,88,53,161,137,139,138 -PE --source-port 53 -oA "${FILE_RESULTS_AVAILABLE_HOSTS}" -v ${HOSTS} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
}

# Function - TCP port scan on discovered hosts
function port_scan_tcp() {
    # Init - customisable
    HOST=${1}
    SCAN_SPEED="T4"
    MIN_HOSTGROUP="50"

    # Init - derived
    DIR_RESULTS_HOST="${DIR_RESULTS}/${HOST}"
    FILE_RESULTS_TCP_ALL="${DIR_RESULTS_HOST}/tcp_all"
    FILE_RESULTS_TCP_ALL_DETAILED="${DIR_RESULTS_HOST}/tcp_all_detailed"

    # Make directory for results
    mkdir -p ${DIR_RESULTS_HOST}

    # Do all TCP ports
    echo ">>>> SCANNING ALL TCP ports in ${HOST}"
    sudo nmap ${OUT_OF_SCOPE_ARG} --min-hostgroup ${MIN_HOSTGROUP} -Pn --disable-arp-ping -${SCAN_SPEED} -sS --source-port 53 -p- -v -oA "${FILE_RESULTS_TCP_ALL}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
    PORTS_TCP_ALL=$(cat "${FILE_RESULTS_TCP_ALL}.nmap" | grep "/tcp " | tr -s " " | cut -d " " -f 1 | cut -d "/" -f 1 | xargs --replace echo -ne {},)
    sudo nmap ${OUT_OF_SCOPE_ARG} --min-hostgroup ${MIN_HOSTGROUP} -Pn --disable-arp-ping -${SCAN_SPEED} -sS --source-port 53 -p ${PORTS_TCP_ALL:0:-1} -sC -sV -v -oA "${FILE_RESULTS_TCP_ALL_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
}

# Function - UDP top ports scan on discovered hosts
function port_scan_udp_top() {
    # Init - customisable
    HOST=${1}
    NUM_TOP_PORTS_UDP=1000
    SCAN_SPEED="T4"
    MIN_HOSTGROUP="50"

    # Init - derived
    DIR_RESULTS_HOST="${DIR_RESULTS}/${HOST}"
    FILE_RESULTS_UDP_TOP="${DIR_RESULTS_HOST}/udp_top_${NUM_TOP_PORTS_UDP}"
    FILE_RESULTS_UDP_TOP_DETAILED="${DIR_RESULTS_HOST}/udp_top_${NUM_TOP_PORTS_UDP}_detailed"

    # Make directory for results
    mkdir -p ${DIR_RESULTS_HOST}

    # Do top UDP ports
    echo ">>>> SCANNING TOP ${NUM_TOP_PORTS_UDP} UDP ports in ${HOST}"
    sudo nmap ${OUT_OF_SCOPE_ARG} --min-hostgroup ${MIN_HOSTGROUP} -Pn --disable-arp-ping -${SCAN_SPEED} -sU --source-port 53 --top-ports ${NUM_TOP_PORTS_UDP} -sC -sV -v -oA "${FILE_RESULTS_UDP_TOP_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
}

# Function - UDP all ports scan on discovered hosts
function port_scan_udp() {
    # Init - customisable
    HOST=${1}
    SCAN_SPEED="T4"
    MIN_HOSTGROUP="50"

    # Init - derived
    DIR_RESULTS_HOST="${DIR_RESULTS}/${HOST}"
    FILE_RESULTS_UDP_ALL="${DIR_RESULTS_HOST}/udp_all"
    FILE_RESULTS_UDP_ALL_DETAILED="${DIR_RESULTS_HOST}/udp_all_detailed"

    # Make directory for results
    mkdir -p ${DIR_RESULTS_HOST}

    # Do all UDP ports
    echo ">>>> SCANNING ALL UDP ports in ${HOST}"
    sudo nmap ${OUT_OF_SCOPE_ARG} --min-hostgroup ${MIN_HOSTGROUP} -Pn --disable-arp-ping -${SCAN_SPEED} -sU -p- -sC -sV -v -oA "${FILE_RESULTS_UDP_ALL_DETAILED}" ${HOST} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
}

# Perform host discovery
host_discovery ${1}

# Perform TCP and UDP port scans on discovered hosts
HOSTS_DISCOVERED=$(cat "${FILE_RESULTS_AVAILABLE_HOSTS}.nmap" | grep "Nmap scan report for" | grep -iv "host down" | cut -d " " -f 5 | xargs --replace={} echo -n "{} ")
for HOST in ${HOSTS_DISCOVERED}; do port_scan_tcp ${HOST}; done;
for HOST in ${HOSTS_DISCOVERED}; do port_scan_udp_top ${HOST}; done;
for HOST in ${HOSTS_DISCOVERED}; do port_scan_udp ${HOST}; done;
