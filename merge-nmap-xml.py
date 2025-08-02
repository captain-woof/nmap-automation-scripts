#!/usr/bin/env python3

import os
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime

def MergeXml(input_dir, output_file):
    """
    Merges multiple Nmap XML files from a directory into a single XML file.

    Args:
        input_dir (str): The path to the directory containing Nmap XML files.
        output_file (str): The path for the merged output XML file.
    """
    xml_files = [f for f in os.listdir(input_dir) if f.endswith('.xml')]
    if not xml_files:
        print("No XML files found in the specified directory.")
        return

    # Use the first file as the base for the merged document
    base_file_path = os.path.join(input_dir, xml_files[0])
    try:
        merged_tree = ET.parse(base_file_path)
        merged_root = merged_tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing base file {xml_files[0]}: {e}")
        return

    # Modify the nmaprun attributes to reflect the merge
    merged_root.set('args', f"nmap (merged from {len(xml_files)} files)")
    merged_root.set('startstr', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


    # Iterate through the rest of the files and append their hosts
    for i in range(1, len(xml_files)):
        file_path = os.path.join(input_dir, xml_files[i])
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for host in root.findall('host'):
                merged_root.append(host)
        except ET.ParseError as e:
            print(f"Warning: Skipping file {xml_files[i]} due to parsing error: {e}")
            continue

    # Update the runstats
    finished = merged_root.find('runstats/finished')
    if finished is not None:
        finished.set('time', str(int(datetime.now().timestamp())))
        finished.set('timestr', datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
        finished.set('summary', f"Merged from {len(xml_files)} files")

    # Write the merged tree to the output file
    try:
        merged_tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"Successfully merged {len(xml_files)} Nmap XML files into {output_file}")
    except IOError as e:
        print(f"Error writing to output file {output_file}: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Merge multiple Nmap XML scan results into a single XML file.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-id', '--input-dir',type=str,help='The directory containing the Nmap XML files to merge.')
    parser.add_argument('-o', '--output-file',type=str,default='./nmap_merged.xml',help='The path for the merged output XML file. Default: "./nmap_merged.xml"')
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' not found.")
    else:
        MergeXml(args.input_dir, args.output_file)