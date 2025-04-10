#!/usr/bin/bash

# Display help
if [[ $1 == "-h" || $1 == "" ]]; then
    echo "Usage: ${0} <HOSTS>";
    exit;
fi

# Init - customisable
HOSTS=${1}
DIR_NAME_RESULTS="nmap"
SCAN_SPEED="T3"

# Init - derived
DIR_RESULTS="${PWD}/${DIR_NAME_RESULTS}"
FILE_RESULTS_HOSTS="${DIR_RESULTS}/available_hosts"

# Make directory for results
if [[ -e ${DIR_RESULTS} ]]; then
    rm -rf ${DIR_RESULTS}
fi
mkdir -p ${DIR_RESULTS}

# Start scan
echo ">>>> STARTING HOSTS DISCOVERY IN ${HOSTS}"
sudo nmap -v -${SCAN_SPEED} -sn -PS[80,8080,8000,443,445,137,139,138,25,587,143,993,110,995,22,21,5985,53,88] -PU[123,88,53] -PE --source-port 53 -oA "${FILE_RESULTS_HOSTS}" ${HOSTS} | tee -a "${DIR_RESULTS}/nmap_logs.txt"
