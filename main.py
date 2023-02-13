import os
import time
import hashlib
import logging
from tqdm import tqdm
import regex
from pdfminer.high_level import extract_text
from nltk import sent_tokenize
import re
import requests
import pandas as pd

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename= r'F:\Python Projects\File Integrity monitoring\log.txt', filemode='w')
file = open(r'path\hashes.csv', 'w')
file.write('Hash, File Name\n')

def virus_total_file_malicious():
    headers = {
        "accept": "application/json",
        "x-apikey": 'API KEY'

    }
    df = pd.read_csv(r'path\hashes.csv')
    for hash in df['Hash']:
        if hash != 'None':
            url = f"https://www.virustotal.com/api/v3/files/{hash}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                    print(f'File {hash} is malicious')
                    logging.critical(f'File {hash} is malicious')
            elif response.status_code == 400:
                print('Try again later')
                exit()
            elif response.status_code == 403:
                print('Forbidden')         
                exit()
            elif response.status_code == 404:
                print('File not found')
                exit()
 
def ioc_extract(file):
    regex_ipv6 = r'([a-f0-9:]+:+)+[a-f0-9]+'
    regex_ipv4 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    regex_filename = r'[A-Za-z0-9-_\·]+\.(txt|php|exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|bat|pdf)'
    regex_filepath = r'[a-z A-Z]:(\\([0-9 a-z A-Z _]+))+'
    regex_sha1 = r'[a-f0-9]{40}|[A-F0-9]{40}'
    regex_sha256 = r'[a-f0-9]{64}|[A-F0-9]{64}'
    regex_sha512 = r'[a-f0-9]{128}|[A-F0-9]{128}'
    regex_md5 = r'[a-f0-9]{32}|[A-F0-9]{32}'
    regex_cve = r'CVE-[0-9]{4}-[0-9]{4,6}'
    regex_domain = r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,6}'
    regex_url = r'(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=∼ _|! : , .;]+[-A-Za-z0-9+&@#/%?=∼ _|]'
    regex_list = {'FILENAME' : regex_filename, 'FILEPATH' : regex_filepath, 'IPV4' : regex_ipv4, 'IPV6' : regex_ipv6, 'SHA1' : regex_sha1, 'SHA256' : regex_sha256, 'SHA512' : regex_sha512, 'MD5' : regex_md5, 'CVE': regex_cve, 'URL' : regex_url, 'DOMAIN' : regex_domain}

    file = open(directory, 'rb')
    
    if file:
        text = extract_text(file)
        text = text.replace('\n', ' ').replace('\r', '').replace('\t', '').replace('\f', '')
        sentences = sent_tokenize(text)
    else:
        file.close()

    entities = []

    for sentence in sentences:
        for key, value in regex_list.items():
            regex = r'\b' + value + r'\b'
            if re.search(regex, sentence, re.IGNORECASE):
                for match in re.finditer(regex, sentence, re.IGNORECASE):
                    entities.append((match.group(), key))

    return entities
        
def calculate_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            chunk = f.read(4096)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(4096)
        return hasher.hexdigest()
    except Exception as e:
        return 'None'
        
def list_files(root_dir):
    files = []
    for dir_path, dir_names, file_names in os.walk(root_dir):
        for file_name in file_names:
            file_path = os.path.join(dir_path, file_name)
            files.append(file_path)
        for dir_name in dir_names:
            dir_path = os.path.join(dir_path, dir_name)
            files.append(dir_path)
    return files
    
def monitor_files(directorty):
    file_list = list_files(directorty)
    for file_name in tqdm(file_list):
        hash = calculate_hash(file_name)
        file.write(f'{hash}, {file_name.replace(",", "_")}\n')
        if os.path.isfile(file_name):
            last_modified = os.path.getmtime(file_name)
            time_difference = time.time() - last_modified
            if time_difference < 86400:
                logging.warning(f'File {file_name} was modified recently | HASH : {hash}')
    file.close()

    
if __name__ == '__main__':
    print("\nFind IOCs on PDF file (1) or Monitor integrity files in a directory (2)")
    choice = input('Enter your choice: ')
    try:
        if choice == '1':
            directory = input('Enter the directory of the PDF file (Specify File path): ')
            entities = ioc_extract(directory)
            for entity in entities:
                print(entity)
            print('"Do you want to check file intergrity? (Y/N)"')
            choice = input('Enter your choice: ')
            if choice == 'Y' or choice == 'y':
                directory = input('Monitoring files in the current directory (File path) : ')
                monitor_files(directory)
            else:
                print('Thank you for using the program')
        elif choice == '2':
            directory = input('Monitoring files in the current directory (File path) : ')
            monitor_files(directory)
            print('Do you want to check whether file is malicious or not? (Y/N)')
            choice = input('Enter your choice: ')
            if choice == 'Y' or choice == 'y':
                virus_total_file_malicious()
        else:
            print('Invalid choice')
    except KeyboardInterrupt:
        print('Program terminated by user')
        exit()
