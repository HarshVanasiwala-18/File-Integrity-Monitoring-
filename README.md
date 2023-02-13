# File-Integrity-Monitoring-

pip install -r req.txt

Important mentione the directory/ path and VirusTotal API. It's is not fully accurate and I am open for your feedback.

The code is a Python script that performs various tasks related to file integrity monitoring. The script includes functions to extract information of interest (IOCs) from a file, check if a file is malicious, and monitor a directory for changes.

The first function, virus_total_file_malicious(), uses the Virus Total API to check if a file is malicious. It reads the hash values of the files from a CSV file and sends a request to the Virus Total API with the hash value. If the file is found to be malicious, a critical log message is written to a log file indicating that the file is malicious.

The second function, ioc_extract(), is used to extract information of interest (IOCs) from a file. It uses the PDFMiner library to extract the text from the file and the Natural Language Toolkit (NLTK) library to split the text into sentences. The function then uses regular expressions to extract different types of IOCs, such as IP addresses, file paths, and hash values. The extracted IOCs are stored in a list and returned by the function.

The final section of the script monitors a directory for changes. It first calculates the hash value of all the files in the directory and stores the file name and hash value in a CSV file. If the hash value of any file has changed, the script logs a message indicating that the file has been modified.
