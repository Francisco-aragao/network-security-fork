# Distributed classification

**Important**: Consult some responsible for the machines to know about the available resources and how to use the LLM model in a distributed way.

The file ```distributed_classification.py``` is a script that handles the distributed classification of vulnerability scanners tools. The classification is done using a LLM model, distributed across multiple machines to gain performance.

Inside the files ```nmap.py```, ```openvas.py```, ```nuclei.py``` and ```metasploit.py``` there are different functions to collect information about each tool. These functions are important to collect the data to specify which prompt will be used for the classification. Inside the file ```constants.py``` exists the prompts to be used for each scenario.

For example, if the nmap current file contains the category 'brute', the classification will be directed to know more information about a file that performs an attack using brute force. The same happens with the other tools.

To run the code, you need to follow:

``` python3 -m venv venv ```

``` source venv/bin/activate ```

``` pip install -r requirements.txt ```

``` python3 distributed_classification.py --SCANNER  <path_to_scanner_files>  --output <output_name> --initialRange INITIAL_RANGE --finalRange FINAL_RANGE --ip_port <LLM_ip_port> ```

Where:

- ```SCANNER``` is one of the following options: nmap, openvas, nuclei, metasploit.
- ```<path_to_scanner_files>``` is the path to the files of the scanner tool to be classified.
- ```<output_name>``` is the name of the output file to store the classification.
- ```INITIAL_RANGE``` is the initial range of the files to be classified (the classification will be performed in 'batch', so a range is necessary).
- ```FINAL_RANGE``` is the final range of the files to be classified.
- ```<LLM_ip_port>``` is the ip and port of the LLM model. It must be in the format: 'ip:port' like '1.2.3.4:5678'.

An example of how to run the code is:

``` python3 distributed_classification.py --nmap ../nmapFolder --openvas ../../openvasFolder --output openvas_nmap_classification_range_0_to_100.json --initialRange 0 --finalRange 100 --ip_port 1.2.3.4:5678 ```
