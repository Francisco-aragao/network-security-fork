import openai
import json

SYSTEM_PROMPT = "You are a world-class AI system, capable of complex reasoning and reflection. Reason through the query inside <thinking> tags, and then provide your final response inside <output> tags. If you detect that you made a mistake in your reasoning at any point, correct yourself inside <reflection> tags."

LLM = openai.OpenAI(
base_url="http://192.168.62.31:50001/v1", # server is running at gorgona1 (cluster is composed by gorgona1, gorgona5 and gorgona6), total VRAM = 72 GB
api_key = "sk-no-key-required"
)      



'''
Focus: Classificate scanners tests by categories:
    - What is detected: for example, which CVEs are checked
    - How is detected: for example, with an exploit, with version check, with an authenticated scan ...

Steps:
Run over all vulns tests
->
Check if there is CVE
-> 
    If CVE exists: tries to classificate in categories HOW is detected
    
    otherwise: tries to check if is the same problem comparing textual information
        if similar texts: classificate in categories

Use dicts for each tool to store the CVEs checked -> will store info about classification
Store all codes without CVE and tries to match them : Brute Force ? Compare by title similarites ?

'''

import os
import re
import json
import argparse
import time

FILE_EXTENSION_OPENVAS = '.nasl'

QOD_VALUE = {
    'exploit': 100,
    'remote_vul': 99,
    'remote_app': 98,
    'package': 97,
    'registry': 97,
    'remote_active': 95,
    'remote_banner': 80,
    'executable_version': 80,
    'default': 75, 
    'remote_analysis': 70,
    'remote_probe': 50,
    'remote_banner_unreliable': 30,
    'executable_version_unreliable': 30,
    'general_note': 1,
    'timeout': 0
}

PROMPT_WHAT_IS_DETECTED = """ 
1.1 Vulnerability: A script can perform a series of actions to detect a vulnerability or a set of vulnerabilities. In most cases a vulnerability is identified by a CVE number, and impacts a set of products identified by CPE numbers. But a vulnerability could be configurations problems on the machine, without a CVE number, allowing bad behaviours.  For scripts that scan a vulnerability, please find: (A) the application under test, (B) the version of the application that is targeted by the script.

1.2 Old Software: Software that is old may no longer receive security updates. As such, these software put systems at higher risk even if there are no known vulnerabilities. Scripts can detect these unmaintained software by checking for end-of-life periods or whether libraries or frameworks have been deprecated. Another case in this category is software that has not received updates that correct security problems. For scripts that identify unmaintained software, please find: (A) the software identified as unmaintained or old software (this can be either an application, package, library, or framework); (B) the version of the software that is searched for, or classified as unmaintained.

1.3 Properties of a System: Scripts may identify properties of a system. Although properties of a system are not vulnerabilities, they can be used by malicious actors to obtain information about the system. For scripts that identify properties of a system, please find: (A) a one-phrase description of the property being identified; (B) the value of the identified property, if applicable.

To complete this task, analyze the detection script code, metadata, comments and verifications to find what is detected, the application, specific targets, and other necessary information. If you cannot find one of the required information, just answer with "Uncertain".

Please fill out the template below. Change only the sections within curly braces, keep the braces on the response, and follow the intructions within the braces considering the explanation above:

What is detected: {select one of Vulnerability, Unmaintained Software, or Property of a System, as described above}
A: {answer to subitem (A) of what is detected}
B: {answer to subitem (B) of what is detected}
"""

CATEGORIES_ATTACK = """
1. Category: Simulated Attack. Description: The script runs tests that simulate real attacks or perform attack-like behaviors, confirming the existence of the vulnerability, performing active probes or making specific and detailed requests to collect information about the target machine.

1.1. Subcategory: External Code Execution. Description: Attempts to execute code or a payload on the target machine from an external connection. If the code attempts to perform malicious actions, gain access over the target, performs buffer overflow or just tests whether it is possible to execute remote code, then it falls into this category.
1.2. Subcategory: Unauthorized Login. Description: Tries to access a running service by guessing potential credentials (like brute force) or hijacking an authenticated user session.
1.3. Subcategory: Protected Information. Description: Attempts to access restricted files, reveal sensitive information, change system settings or machine parameters or gain privileged access that should be protected and inaccessible to unauthorized users.
1.4. Subcategory: Denial of Service (DoS). Description: Attempts to disrupt or overload a service, making it unavailable to legitimate users.
1.5. Subcategory: Privileged Attack. Description: Attempts to exploit vulnerabilities with memory manipulation, payloads or remote code execution through credentials provided by the user in the tool parameters. If the code has as parameters, access credentials necessary for its operation then it falls into this category.
"""

CATEGORIES_PRIVILEGED = """
2. Category: Privileged Scan. Description: Performs scans with privileged information, like (i) credentials provided by the user to specific services, (ii) when running inside the target machine directly or (iii) runs the tests with privileged permissions or access. The script may run internal commands and gather detailed info about installed packages and configurations.

2.1. Subcategory: Package List. Description: Extracts the list of installed packages to check the versions of running services and correlate them with known vulnerabilities. If the code looks for some application or service in a list or registry of installed packages, then it falls into that subcategory.
2.2. Subcategory: Service information. Description: Reviews the configuration of services, files, and security policies to identify misconfigurations that could expose the system to risks or collect information about the target machine.
2.3. Subcategory: Log File Analysis. Description: Analyzes system logs for suspicious activity, potential security incidents, or errors that could indicate misconfigurations or breaches.
"""

CATEGORIES_BASIC_REQUEST = """
3. Category: Basic Active Requests. Description: The script gathers information by making simple requests or observing data that the target system passively exposes such as responde banners with software version, configuration details, URLs or open services. The test does not require authentication, perform any intrusive actions, authentication attempts, attack simulations, nor crafts specific packets for requests.

3.1. Subcategory: Banner Check. Description: Checks software information, application version, HTTP status code or the running service based on the initial response (banner) sent by the server after basic interaction from the scanner. Returns inferred vulnerabilities or the information collected just sendind simple requests and checking elements of the response. If a code performs a request and just check the response once, then enters in this subcategory.
3.2. Subcategory: URL Presence Check. Description: Identifies the vulnerabilities checking if exists vulnerable URLs or paths on the target. The tested URL is present in the code and represents the vulnerability. The URL is not provided by the user as a parameter for executing the script. If the vulnerability is detected by the presence of the URL, then the code falls into this category.
3.3. Subcategory: Discovery. Description: Executes other actions to test the existence of the vulnerability without actually exploiting it, or performs active probing to just collect information about the target machine.
"""

PROMPT_CATEGORIES = """
To complete this task, analyze the detection script code, metadata, comments and verifications to find how the detection is made. First identify the category of a script, and then the subcategory. If none of the categories match the detection script, propose a new category. If a category matches the detection script but no existing subcategory matches the detection script, please propose a new subcategory. Please, to answer the question, fill out the template below. Change only the sections within curly braces, keep the braces on the response, and follow the intructions within the braces considering the explanation above:

How the script works?
Category: {Category}
Subcategory: {Subcategory}
Explanations: {explanation about the code}

If a subcategory matches the script, please simply report the number of the subcategory and do not provide any additional explanation. If no match is found, please propose and describe a new category or subcategory.

Think carefully.
"""

PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Auxiliary modules 
Module description: Auxiliary modules do not exploit a target, but can perform useful tasks such as:

Administration - Modify, operate, or manipulate something on target machine
Analyzing - Tools that perform analysis, mostly password cracking
Gathering - Gather, collect, or enumerate data from a single target
Denial of Service - Crash or slow a target machine or service
Scanning - Scan targets for known vulnerabilities
Server Support - Run Servers for common protocols such as SMB, FTP, etc

=====

Module name: Encoder modules
Module description: Encoders take the raw bytes of a payload and run some sort of encoding algorithm, like bitwise XOR. These modules are useful for encoding bad characters such as null bytes.

=====

Module name: Evasion modules 
Module description: Evasion modules give Framework users the ability to generate evasive payloads that aim to evade AntiVirus, such as Windows Defender, without having to install external tools.

=====

Module name: Nop modules
Module description: Nop modules, short for ‘No Operation’, generate a sequence of ‘No Operation’ instructions that perform no side-effects. NOPs are often used in conjunction with stack buffer overflows.

=====

Module name: Payloads modules 
Module description: In the context of Metasploit exploit modules, payload modules encapsulate the arbitrary code (shellcode) that is executed as the result of an exploit succeeding. This normally involves the creation of a Metasploit session, but may instead execute code such as adding user accounts, or executing a simple pingback command that verifies that code execution was successful against a vulnerable target.

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """
#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_BASIC_REQUEST + PROMPT_CATEGORIES

PROMPT_METASPLOIT_EXPLOIT = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_ATTACK + PROMPT_CATEGORIES

PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED


PROMPT_METASPLOIT_PRIVILEGED = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Auxiliary modules 
Module description: Auxiliary modules do not exploit a target, but can perform useful tasks such as:

Administration - Modify, operate, or manipulate something on target machine
Analyzing - Tools that perform analysis, mostly password cracking
Gathering - Gather, collect, or enumerate data from a single target
Denial of Service - Crash or slow a target machine or service
Scanning - Scan targets for known vulnerabilities
Server Support - Run Servers for common protocols such as SMB, FTP, etc

=====

Module name: Encoder modules
Module description: Encoders take the raw bytes of a payload and run some sort of encoding algorithm, like bitwise XOR. These modules are useful for encoding bad characters such as null bytes.

=====

Module name: Evasion modules 
Module description: Evasion modules give Framework users the ability to generate evasive payloads that aim to evade AntiVirus, such as Windows Defender, without having to install external tools.

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

Module name: Nop modules
Module description: Nop modules, short for ‘No Operation’, generate a sequence of ‘No Operation’ instructions that perform no side-effects. NOPs are often used in conjunction with stack buffer overflows.

=====

Module name: Payloads modules 
Module description: In the context of Metasploit exploit modules, payload modules encapsulate the arbitrary code (shellcode) that is executed as the result of an exploit succeeding. This normally involves the creation of a Metasploit session, but may instead execute code such as adding user accounts, or executing a simple pingback command that verifies that code execution was successful against a vulnerable target.

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_ATTACK + PROMPT_CATEGORIES

PROMPT_NUCLEI = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

An Nuclei template can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an Nuclei template works

An Nuclei template can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_ATTACK + CATEGORIES_PRIVILEGED + CATEGORIES_BASIC_REQUEST + PROMPT_CATEGORIES

PROMPT_NMAP = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an Nmap script works

An Nmap script can work in many different ways. Pay attention in required arguments that , if exists, could indicate privileged information needed by the scan. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_ATTACK + CATEGORIES_PRIVILEGED + CATEGORIES_BASIC_REQUEST + PROMPT_CATEGORIES

PROMPT_NMAP_BRUTE_DOS = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED 

PROMPT_NMAP_DISCOVERY  = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED 

PROMPT_NMAP_ATTACK  = """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

""" + CATEGORIES_ATTACK + PROMPT_CATEGORIES 


PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED = """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:

=====
QOD Value: 99%
QOD Name: Remote Vulnerability
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerability.

=====
QOD Value: 98%
QOD Name: Remote Application
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerable application.

=====

QOD Value: 95%
QOD Name: Remote Active
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response shows the likely presence of the vulnerable application or of the vulnerability. "Likely" means that only rare circumstances are possible in which the detection would be wrong.

=====
QOD Value: 80%
QOD Name: Remote Banner
Description: Remote banner checks of applications that offer patch level in version. Many proprietary products do so.

=====
QOD Value: 80 %
QOD Name: Executable Version
Description: Authenticated executable version checks for Linux(oid) or Microsoft Windows systems where applications offer patch level in version.

=====
QOD Value: 30 %
QOD Name: Executable Version Unreliable
Description: Authenticated executable version checks for Linux(oid) systems where applications do not offer patch level in version identification.

=====
QOD Value: 1 %
QOD Name: General Note
Description: General note on potential vulnerability without finding any present application.

=====
QOD Value: 0 %
QOD Name: Timeout
Description: The test was unable to determine a result before it was ended by timeout.

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_BASIC_REQUEST + PROMPT_CATEGORIES

PROMPT_OPENVAS_EXPLOIT = """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:

=====
QOD Value: 100%
QOD Name: Exploit
Description: The detection happened via an exploit and is therefore fully verified.

=====

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_ATTACK + PROMPT_CATEGORIES

PROMPT_OPENVAS_AUTHENTICATED = """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:


=====
QOD Value: 97%
QOD Name: Package
Description: Authenticated package-based checks for Linux(oid) systems. This category refers to authenticated scans.

=====
QOD Value: 97%
QOD Name: Registry
Description: Authenticated registry based checks for Microsoft Windows systems. This category refers to authenticated scans.

=====

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

""" + PROMPT_WHAT_IS_DETECTED + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

""" + CATEGORIES_PRIVILEGED + PROMPT_CATEGORIES


def classification_text_generation(content, prompt):

    user_prompt = f"""
    {content}
    {prompt}
    """

    out = LLM.chat.completions.create(
        model="llama-3-70b-q6",
        messages = [
            {
                "role": "system",
                "content": f"{SYSTEM_PROMPT}"
            },
            {
                "role": "user",
                "content": f"{user_prompt}"
            }
        ],
        max_tokens=None,
    )

    return out.choices[0].message.content


def find_key_by_value(input_dict, value):
    keys = [key for key, val in input_dict.items() if val == value]
    return keys

# Try to read file with different encodings
def read_file_with_fallback(file_path):


    if not os.path.exists(file_path):
        print(file_path)
        raise Exception('Arquivo não existe')
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='iso-8859-1') as f:
            return f.read()

def extract_privileged_metasploit(content):
    # Regular expression to match 'Privileged' => true,
    match = re.search(r"'Privileged'\s*=>\s*(true|false)\s*,", content, re.IGNORECASE)
    
    if match:
        return match.group(1)
    else:
        return None

# find the CVEs related to the nmap file
def extract_cve_from_nmap(nmap_file):
    cve_regex = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'([^']+)'.*\}")
    content = read_file_with_fallback(nmap_file)
    cves = cve_regex.findall(content)
    return cves

def extract_cve_from_openvas(content): # esse regex ta ruim, não ta pegando todos os cves: /home/franciscoaragao/folderVulnsTests/openvas/smtp_relay.nasl -> não pegou todos

    cve_regex = re.compile(r'script_cve_id\("([^"]+)"(?:,\s*"([^"]+)")*\);')
    cves = cve_regex.findall(content)
    cves_to_list = [cve for match in cves for cve in match if cve]

    return cves_to_list

def extract_cve_from_metasploit(metasploit_file):
    """ Extract CVE identifiers from a Metasploit file. """
    #content = read_file_with_fallback(metasploit_file)
    cve_pattern = re.compile(r"\[\s*'CVE'\s*,\s*'(\d{4}-\d+)'\s*\]")
    cves = cve_pattern.findall(metasploit_file)

    for i in range(len(cves)): # adding word cve in cve list because the regex dont match it
        cves[i] = 'CVE-' + cves[i]
    return cves

def extract_rank_from_metasploit(metasploit_file):
    """ Extract rank values from a Metasploit file. """
    #content = read_file_with_fallback(metasploit_file)
    rank_pattern = re.compile(r'Rank\s*=\s*(\w*)')

    rank = rank_pattern.search(metasploit_file)

    return rank.group(1) if rank else None

def extract_module_metasploit(metasploit_file):
    """ Extract module type (Auxiliary, Post, Exploit) from a Metasploit file. """
    #content = read_file_with_fallback(metasploit_file)
    module_type_pattern = re.compile(r'class\s+MetasploitModule\s+<\s*Msf::(\w+)')
    match = module_type_pattern.search(metasploit_file)
    return match.group(1) if match else None


def is_openvas_file_deprecated(file_content):
    deprecated_regex = re.compile(r'script_tag\(name:"deprecated",\s*value:TRUE\);')
    return deprecated_regex.search(file_content) is not None


def extract_qod_openvas(content):    

    qod_regex = re.compile(r'script_tag\(name:"(qod|qod_type)",\s*value:"([^"]+)"\);')

    qod_match = qod_regex.search(content)
    
    if not qod_match:
        return ''
    
    qod_type = ''
    qod_value = 0

    # skipping this case because if only the number, its not possible to know the qod_type
    if qod_match.group(2).isdigit(): # return the value in regex. Could be qod_type or string
        qod_value = int(qod_match.group(2))
        qod_type = find_key_by_value(QOD_VALUE, qod_value)           

        return ''         
    else:
        qod_type = qod_match.group(2)
        qod_value = QOD_VALUE[qod_type] if qod_type in QOD_VALUE else None

    if qod_value is None:
        return ''

    return qod_type, qod_value


def extract_cve_nuclei(content):
    """ Descricao """
    
    cve_regex = re.compile(r'cve-id:\s*(CVE-[\d-]+)')
    cves = cve_regex.findall(content)
    
    return cves if cves else ''



def extract_cve_nmap(content):

    cve_regex = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'([^']+)'.*\}")
    cves = cve_regex.findall(content)
    return cves if cves else ''

def extract_categorie_nmap(content):

    categorie_regex = re.compile(r'categories\s*=\s*\{([^\}]+)\}')
    categories = categorie_regex.findall(content)

    result = ''
    if categories:
        words = [word.strip('"') for word in categories[0].split(',')]
        result = ' '.join(words)

    return result

def analysis_metasploit_modules(metasploit_folder):
    
    modules_with_no_CVE = []

    metasploit_info = []

    metasploit_files = [os.path.join(root, file)
                     for root, _, files in os.walk(metasploit_folder)
                     for file in files if file.endswith('.rb')]
    

    for metasploit_file in metasploit_files[:350]:

        content = read_file_with_fallback(metasploit_file)

        cves = extract_cve_from_metasploit(content)
        
        if not (cves):

            modules_with_no_CVE.append(metasploit_file)
            #continue

        module = extract_module_metasploit(content)

        print("requisitando modelo")
        start_time = time.time()
        
        privileged = extract_privileged_metasploit(content)
        print('---> ', privileged)

        if privileged == 'true' and module == 'Exploit' :
            classification = classification_text_generation(content, PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED)
            
            category_privileged_exploit = """ 

            How the script works?
            Category: {Simulated Attack}
            Subcategory: {Privileged Attack}

            """

            classification += category_privileged_exploit

        elif privileged == 'true':
            classification = classification_text_generation(content,  PROMPT_METASPLOIT_PRIVILEGED)
        elif module == 'Exploit':
            classification = classification_text_generation(content,  PROMPT_METASPLOIT_EXPLOIT)
        else:
            classification = classification_text_generation(content,  PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        print("resposta modelo")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")


        info = {
            'file': metasploit_file,
            'cves': cves,
            'module': module, 
            'privileged': privileged,
            'classification': classification,
        }

        metasploit_info.append(info)


    return metasploit_info, modules_with_no_CVE


def analysis_openvas_NVTS(openvas_folder):

    NVTS_with_no_CVE = []

    openvas_info = []

    """ openvas_files = [os.path.join(root, file)
                     for root, _, files in os.walk(openvas_folder)
                     for file in files if file.endswith(FILE_EXTENSION_OPENVAS)] """

    # openvas unique files obtained by 'teste_simil'.
    with open('/home/grad/ccomp/22/gabriel.cardoso/gt-crivo/unique_files_op.txt', 'r') as file:
        # Use a list comprehension to strip whitespace and store each path
        openvas_files = [line.strip() for line in file]
    
    
    for openvas_file in openvas_files[:350]:

        content = read_file_with_fallback(openvas_file)

        if is_openvas_file_deprecated(content):
            continue

        qod_info = extract_qod_openvas(content)

        if not qod_info:
            continue
            
        cves = extract_cve_from_openvas(content) # conferir esse regex
        
        if not (cves):

            NVTS_with_no_CVE.append(openvas_file)
            #continue
        

        qod_type = qod_info[0] if qod_info else ''
        qod_value = qod_info[1] if qod_info else ''
        
        print("requisitando modelo")
        start_time = time.time()

        if qod_type == 'exploit':
            classification = classification_text_generation(content, PROMPT_OPENVAS_EXPLOIT)
        elif qod_value == 97 or qod_type == 'executable_version':
            classification = classification_text_generation(content, PROMPT_OPENVAS_AUTHENTICATED)
        else:
            classification = classification_text_generation(content, PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED)
            
        end_time = time.time()
        elapsed_time = end_time - start_time
        print("resposta modelo")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")


        info = {
            'file': openvas_file,
            'qod': qod_info,
            'cves': cves,
            #'description': summary,
            #'detectionMethod': vuldetect,
            #'ports': ports,
            #'name': name,
            'classification': classification,
        }

        openvas_info.append(info)


    return openvas_info, NVTS_with_no_CVE


def analysis_nuclei_templates(nuclei_folder):
    
    templates_with_no_CVE = []

    nuclei_info = []

    nuclei_files = [os.path.join(root, file)
                     for root, _, files in os.walk(nuclei_folder)
                     for file in files if file.endswith('.yaml')]
    

    for nuclei_file in nuclei_files[:350]:

        content = read_file_with_fallback(nuclei_file)

        cves = extract_cve_nuclei(content)
        
        if not (cves):

            templates_with_no_CVE.append(nuclei_file)


        print("requisitando modelo")
        start_time = time.time()
        classification = classification_text_generation(content, PROMPT_NUCLEI)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print("resposta modelo")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")

        info = {
            'file': nuclei_file,
            'cves': cves,
            #'name': name,
            #'description': description,
            #'vendor': vendor,
            #'product': product,
            'classification': classification,
        }

        nuclei_info.append(info)


    return nuclei_info, templates_with_no_CVE

def analysis_nmap_scripts(nuclei_folder):
    
    scripts_with_no_CVE = []

    nmap_info = []

    nmap_files = [os.path.join(root, file)
                     for root, _, files in os.walk(nuclei_folder)
                     for file in files if file.endswith('.nse')]
    
    for nmap_file in nmap_files[:350]:

        content = read_file_with_fallback(nmap_file)

        cves = extract_cve_nmap(content)
        
        if not (cves):

            scripts_with_no_CVE.append(nmap_file)
            #continue

        # description, categories = collect_nmap_info(content)

        categorie = extract_categorie_nmap(content)

        file_name = nmap_file.split('/')[-1]

        print("requisitando modelo")
        start_time = time.time()

        if 'brute' in categorie:
            classification = classification_text_generation(content, PROMPT_NMAP_BRUTE_DOS)

            category_privileged_exploit = """ 

            How the script works?
            Category: {Simulated Attack}
            Subcategory: {Unauthorized Login}

            """

            classification += category_privileged_exploit
        
        elif 'dos' in categorie:
            classification = classification_text_generation(content, PROMPT_NMAP_BRUTE_DOS)

            category_privileged_exploit = """ 

            How the script works?
            Category: {Simulated Attack}
            Subcategory: {Denial of Service (DoS)}

            """

            classification += category_privileged_exploit

        elif 'discovery' in categorie and 'safe' in categorie: # 'safe' included because there is 'intrusive' codes that receives 'discovery' categorie but performs attacks
            classification = classification_text_generation(content, PROMPT_NMAP_DISCOVERY)

            category_privileged_exploit = """ 

            How the script works?
            Category: {Basic Active Requests}
            Subcategory: {Discovery}

            """

            classification += category_privileged_exploit
        
        elif ('exploit' in categorie or 'malware' in categorie or 'vuln' in categorie) and 'safe' not in categorie: 

            classification = classification_text_generation(content, PROMPT_NMAP_ATTACK)

        else:
            classification = classification_text_generation(content, PROMPT_NMAP)
        
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        print("resposta modelo")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")


        if classification != '':
            countClassified += 1
        else:
            countNotClassified += 1

        info = {
            'file': nmap_file,
            'cves': cves,
            'name': file_name,
            #'categories': categories,
            #'description': description,
            'classification': classification,
        }

        nmap_info.append(info)

    return nmap_info, scripts_with_no_CVE

def compare_similarity(file_path1, file_path2):

    content1 = read_file_with_fallback(file_path1)
    content2 = read_file_with_fallback(file_path2)

    if 'nmap' in file_path1:
        description, categories = collect_nmap_info(content1)

        file_name = file_path1.split('/')[-1]

        metadata_merged1 = file_name + ' ' + description + ' ' + categories

    elif 'openvas' in file_path1:

        qod_info = extract_qod_openvas(content1)

        summary, vuldetect, ports, name, family, software_affected = collect_openvas_info(file_path1)

        qod_type = qod_info[0] if qod_info else ''
        
        metadata_merged1 = summary + ' ' +  vuldetect + ' ' + name + ' ' +  ' ' + qod_type + ' ' + family + ' ' + software_affected

    elif 'nuclei' in file_path1:

        name, description, vendor, product = collect_nuclei_info(content1)
        
        metadata_merged1 = name + ' ' + description
    
    if 'nmap' in file_path2:
        description, categories = collect_nmap_info(content2)

        file_name = file_path2.split('/')[-1]

        metadata_merged2 = file_name + ' ' + description + ' ' + categories
    elif 'openvas' in file_path2:

        qod_info = extract_qod_openvas(content2)

        summary, vuldetect, ports, name, family, software_affected = collect_openvas_info(file_path2)

        qod_type = qod_info[0] if qod_info else ''
        
        metadata_merged2 = summary + ' ' +  vuldetect + ' ' + name + ' ' +  ' ' + qod_type + ' ' + family + ' ' + software_affected
    elif 'nuclei' in file_path2:

        name, description, vendor, product = collect_nuclei_info(content2)
        
        metadata_merged2 = name + ' '  + description
    
    simil = classification_similarity(metadata_merged1, metadata_merged2)

    return True if simil > 0.5 else False 


def analysis_tests_no_cve(list_tests_no_cve):

    tools = ['nmap', 'openvas', 'nuclei']

    current_tools_code = ''
    for i in range(len(list_tests_no_cve)):
        for t in tools:
            if t in list_tests_no_cve[i]:
                current_tools_code = t
        
        for j in range(i, len(list_tests_no_cve)):
            if current_tools_code in list_tests_no_cve[j]:
                continue

            simil_file_name = classification_similarity(list_tests_no_cve[i].split('/')[-1].split('.')[0], list_tests_no_cve[j].split('/')[-1].split('.')[0])

            """ print('simil file name: ', simil_file_name)
            print() """

            if simil_file_name > 0.6:
                print(list_tests_no_cve[i])
                print(list_tests_no_cve[j])

                print(compare_similarity(list_tests_no_cve[i], list_tests_no_cve[j]))
                print()




if __name__ == '__main__':


    parser = argparse.ArgumentParser(description="Match CVEs between Nmap, OpenVAS, and Nuclei templates.")
    parser.add_argument("--nmap", required=False, help="Path to the Nmap directory.")
    parser.add_argument("--openvas", required=False, help="Path to the OpenVAS directory.")
    parser.add_argument("--nuclei", required=False, help="Path to the Nuclei templates directory.")
    parser.add_argument("--metasploit", required=False, help="Path to the metasploit templates directory.")
    parser.add_argument("--noCVE", required=False, help="Analyse tests without CVE.")
    parser.add_argument("--output", required=False, help="Output JSON file.")
    parser.add_argument("--qod_summary", required=False, help="Output JSON file for QOD summary.")

    args = parser.parse_args()

    tests_with_no_CVE = []
    results = {}

    if args.nuclei:
        nuclei_info, templates_with_no_CVE = analysis_nuclei_templates(args.nuclei)

        results['nuclei'] = {}
        results['nuclei'] = nuclei_info
        tests_with_no_CVE += templates_with_no_CVE    

    if args.openvas:
        openvas_info, NVTS_with_no_CVE = analysis_openvas_NVTS(args.openvas)

        results['openvas'] = {}
        results['openvas'] = openvas_info
        tests_with_no_CVE += NVTS_with_no_CVE

    if args.nmap:
        nmap_info, scripts_with_no_CVE = analysis_nmap_scripts(args.nmap)

        results['nmap'] = {}
        results['nmap'] = nmap_info
        tests_with_no_CVE += scripts_with_no_CVE
    
    if args.metasploit:
        metasploit_info, modules_with_no_CVE = analysis_metasploit_modules(args.metasploit)

        results['metasploit'] = {}
        results['metasploit'] = metasploit_info
        tests_with_no_CVE += modules_with_no_CVE
    
    if args.nmap or args.nuclei or args.openvas or args.metasploit:
        results['tests_with_no_CVE'] = tests_with_no_CVE
    
    """  if args.noCVE:
        if results != {}:
            
            if 'tests_with_no_CVE' not in results:
                raise

            analysis_tests_no_cve(results['tests_with_no_CVE'])
        else:
            with open(args.noCVE, 'r') as f:
                data = json.load(f)            

            if 'tests_with_no_CVE' not in data:
                raise

            analysis_tests_no_cve(data['tests_with_no_CVE']) """            

    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)
    
