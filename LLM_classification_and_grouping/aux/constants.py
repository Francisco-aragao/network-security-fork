"""
This module defines all constants used for the classification task.

The classification task categorizes files along two dimensions:
1. **What is detected**:
   - Vulnerability
   - Unmaintained software
   - System property
2. **How it is detected**:
   - Simulated attack
   - Privileged scan
   - Basic active requests
   - (and the subcategories)

For each scanner action, a specific prompt is provided to guide the AI towards the appropriate classification while excluding irrelevant options. These prompts were crafted through script analysis and extensive experimentation.

All prompts used for this task are stored in `.txt` files located in the 'prompts' folder.
"""



with open("../prompts/prompt_system.txt", "r") as f:
    SYSTEM_PROMPT = f.read()

with open("../prompts/_what_is_detected_attack.txt", "r") as f:
    WHAT_IS_DETECTED_ATTACK = f.read()

with open("../prompts/_what_is_detected_proerties.txt", "r") as f:
    WHAT_IS_DETECTED_PROPERTIES = f.read()

with open("../prompts/_what_is_detected_old_software.txt", "r") as f:
    WHAT_IS_DETECTED_OLD_SOFTWARE = f.read()

with open("../prompts/prompt_what_is_detected.txt", "r") as f:
    PROMPT_WHAT_IS_DETECTED = f.read()

with open("../prompts/categorie_attack.txt", "r") as f:
    CATEGORIE_ATTACK = f.read()

with open("../prompts/categorie_privileged.txt", "r") as f:
    CATEGORIE_PRIVILEGED = f.read()

with open("../prompts/categorie_basic_request.txt", "r") as f:
    CATEGORIE_BASIC_REQUEST = f.read()

with open("../prompts/prompt_categories.txt", "r") as f:
    PROMPT_CATEGORIES = f.read()

with open("../prompts/prompt_compare_similarity.txt", "r") as f:
    PROMPT_COMPARE_SIMILARITY = f.read()

with open("../prompts/qod_info.txt", "r") as f:
    QOD_INFO = f.read()

with open("../prompts/ranking_info.txt", "r") as f:
    RANKING_INFO = f.read()

with open("../prompts/modules_info.txt", "r") as f:
    MODULES_INFO = f.read()

######### METASPLOIT ##################

PROMPT_METASPLOIT_POST = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """
#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_PRIVILEGED
    + PROMPT_CATEGORIES
)


PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

""" + MODULES_INFO
+ """

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """
#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_BASIC_REQUEST
    + PROMPT_CATEGORIES
)


PROMPT_METASPLOIT_EXPLOIT = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

""" + RANKING_INFO
+ """

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + PROMPT_CATEGORIES
)

PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

""" + RANKING_INFO
+ """

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
)


PROMPT_METASPLOIT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

""" + MODULES_INFO
+ """ 
#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

""" + RANKING_INFO
+ """

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + PROMPT_CATEGORIES
)

######### NUCLEI ##################

PROMPT_NUCLEI = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

An Nuclei template can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Nuclei template works

An Nuclei template can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + CATEGORIE_PRIVILEGED
    + CATEGORIE_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_NUCLEI_REMOTE_CODE_EXECUTION = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
)

PROMPT_NUCLEI_AUTH_BYPASS = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
)

######### NMAP ##################

PROMPT_NMAP = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Nmap script works

An Nmap script can work in many different ways. Pay attention in required arguments that , if exists, could indicate privileged information needed by the scan. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + CATEGORIE_PRIVILEGED
    + CATEGORIE_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_NMAP_BRUTE_DOS = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
)

PROMPT_NMAP_DISCOVERY = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
)

PROMPT_NMAP_ATTACK = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Nmap script works

An Nmap script can work in many different ways. Pay attention in required arguments that , if exists, could indicate privileged information needed by the scan. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + PROMPT_CATEGORIES
)

########## OPENVAS ##################

PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED = (
    """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:

""" 
+ QOD_INFO
+ """

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_OPENVAS_EXPLOIT = (
    """     
            
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

"""
    + WHAT_IS_DETECTED_ATTACK
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_ATTACK
    + PROMPT_CATEGORIES
)

PROMPT_OPENVAS_AUTHENTICATED = (
    """     
            
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

"""
    + WHAT_IS_DETECTED_ATTACK
    + WHAT_IS_DETECTED_PROPERTIES
    + WHAT_IS_DETECTED_OLD_SOFTWARE
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIE_PRIVILEGED
    + PROMPT_CATEGORIES
)

