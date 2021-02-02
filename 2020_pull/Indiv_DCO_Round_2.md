## Background
You're provided remote access to an infected system via GRR Rapid Response.  There is a rogue process named `nslookup.exe` running on the system.
## Getting Started
Your first task is to perform remote live forensics of the infected system using GRR Rapid Response and determine the indicators of compromise associated with the rogue process. For this task, you'll be graded on the following questions. 
Q1. Where is the process executable located on the disk?
Q2. What is the autorun registry key associated with the rogue process?
Q3. Provide the `Name` of the firewall rule associated with the rogue process.
Your next task is to utilize the IOC information and remotely clean the infected system, again via GRR Rapid Response. For this second task, you will earn points if -
Grading Check 1 - Rogue process is stopped
Grading Check 2 - Process executable is deleted
Grading Check 3 - Autorun registry key associated with the rogue process is deleted
Grading Check 4 - Firewall rule associated with the rogue process is deleted (not just disabled)
A grading script is executed every 2 minutes and the results are published to `http://192.168.10.102`.
Please note -
* The Grading results URL (`http://192.168.10.102`) and GRR Web Console (`http://192.168.10.100:8000`) are both accessible from the `Analyst` VM. 
* The hostname of the infected system is `WIN-GRR-01`.
* The GRR client is installed on the infected system and is reporting to the GRR server.
* Try using the browser level refresh button if at times  the directory listing does not appear even after using the refresh button within the `GRR Virtual Filesystem`.
## Submission Format
Submission format for the three questions and grading checks is as follows - 
Part 1 of 7:  Absolute path including the executable name
```
C:\\Users\\Student\\abc.exe
``` 
Part 2 of 7: Absolute path including the registry key 
```
/HKEY_CURRENT_USER/Control Panel/Accessibility/Warning Sounds
```
Part 3 of 7: `Name` of the firewall rule (phrase comprising of 2 - 5 words)
```
Key Management Service
```
Part 4 of 7: Grading Check 1 (string of random characters)
```
bi4uv6ngbc
```
Part 5 of 7: Grading Check 2 (string of random characters)
```
tgu965cfsn
```
Part 6 of 7: Grading Check 3 (string of random characters)
```
bs67pdq4vc
```
Part 7 of 7: Grading Check 4 (string of random characters)
```
qgujm1xk89
```

## System and Tool Credentials
  | system/tool | username | password |
  |-------------|----------|----------|
  | Analyst  | user     | tartans  |
  | Grr-Server     | user     | tartans  |
  | Grr-Server Web Console       | admin    | tartans  |






# PFirewall PFun
## Background  
Two network sites wish to be connected via a VPN tunnel. A simple network map of these two sites is included below. 
Site 2 (the remote site) has already configured their side of the VPN tunnel with the following settings:  
- IPSec Encapsulating Security Payload IPv4 Tunnel
- SHA512 Hashing
- 256bit AES Encryption
- Diffie Helman & PFK  Group 16 (4096 bit) Key Negotiation  
- Pre-Shared Key:  `tartans`
Your first task is to configure the Site 1 (local site) PFSense firewall to match the settings of the Site 2 firewall and complete the tunnel connection. 
Once the VPN tunnel is completed, you must configure the Site 1 firewall to have the following settings:
- Allow inbound TCP connections on port 12345 and block all other inbound ports
- Limit Bandwidth to/from Site 2 to 1Mbps
Important Note: There are iperf servers running on the Site 1 Workstation VM that are required to remain running for grading to succeed. Do not manually terminate the Powershell window that may briefly show on the workstation screen. 
## Network Map
![network-map](https://files-presidentscup.cisa.gov/img/a12-network-map.png)
## Getting Started
Visit the Site 1 PFSense firewall web configuration panel at http://192.168.100.1. The credentials for this site are in the section below. This is where you will make the required firewall changes. 
## Submission Format
This challenge will use an in-game grading website to assess your network configurations.   
Once you have the VPN tunnel properly configured, you can visit the website http://grade.me which is running on the grading server in Site 2. Click the button on the website to grade your progress and receive tokens. 
The submission for all parts of this challenge will be a 16 character ASCII string. All letters will be lower case.
There are 3 parts to a submission which correlate to each the firewall changes that need to be made.   Visit http://grade.me to grade the environment and receive tokens to submit. 
Example submission:  
**Grading Check 1: Block connections on incoming ports**
```
abcdefghijklmnop
```
**Grading Check 2: Allow incoming TCP connections on port 12345**
```
abcdefghijklmnop
```
**Grading Check 3: Limit traffic bandwidth to 1Mbps**
```
abcdefghijklmnop
```
## System Credentials
| system      | username | password |
|----------------|----------|----------|
| Site1Workstation        | user | tartans  |
| Site1Firewall  <br> (PFSense Web Console) | admin | tartans




# Dark Dominoes
## Getting started
Over the past weekend, there was an alert that suspicious traffic has been coming in and out of a machine within your network.
Your organization fears that the machine has been infected and has asked you to come in and investigate.
It is unknown at this time exactly what has occurred and what information is being transferred. You must determine what is causing these events and 
dispose of any malicious files or scripts that may be on the machine.    
You will have access to one Kali Linux machine; use the tools available to you to locate and remove the cause of the suspicious events that are taking place.
## Submission Format
For this challenge your task is to eradicate the three main malicious scripts being executed. There will be a grading script that you can execute and when you have successfully mitigated the main threats on your machine, you will get a file sent to your Desktop that will contain the answer. 
In order to run the grading script, run the command `checker` at the terminal and it will execute.
## Example submission
When entering your submissions, please enter them in the following format:
Example submission:
```
secretTime
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| user          | user     | tartans  |






> Download Resources: [ISO File 68.7MB](https://files-presidentscup.cisa.gov/a08-2oxvzr6q0n49nvld.iso)
  # More Than Meets the Eye - Dark of the JPGs
  ## Background
Attackers took photos in the University of Pittsburgh, Pittsburgh, PA area on the morning of July 5th using a Samsung Galaxy S7 phone (SM-G930V camera model). It is believed that the buildings/subjects of these photos are currently the targets and victims of ransomware attacks. The attackers' location was traced, and evidence was recovered at the scene. 
Evidence suggests that embedded within these images are the codes to decrypt the ransomware and regain all locked files on the respective location's systems.
  ## Getting Started
The challenge data has been attached to your system's CD drive in a folder called \"Challenge Data\". You will find four sets with five jpg image files in each set.
Your first task is to identify the image file within each of the four sets that matches the correct date, July 5th, when taken (not the file creation date itself), the correct phone/camera model mentioned above, and also where the latitude/longitude data matches the physical location of the subject of the image (referenced in the image filename). You will be required to analyze the exif data for each image in order to do this. Internet location research is recommended for location lookups.
Once you have identified the correct images to investigate, one per set, you must analyze the images to find the codes hidden within. Each code is hidden in a unique way and every image contains a hidden code in some fashion. Therefore the existence of a code does not mean you are looking at the correct file. Decryption codes will be hidden by methods of varying difficulty and complexity. Since there are 4 sets, the codes are hidden in 4 unique ways, and each image within a set has the code hidden in the same manner.
  ## Winning Conditions
You must find all 4 codes in order to receive full credit for this challenge. Codes have score values commensurate with the relative difficulty in finding them.
## Submission Format
Each code is an 8-character string using numerals and lowercase letters only. 1 (numeral 1) and l (lowercase L) will not be included to avoid confusion between the two.
All 4 parts will follow the same token format for submission.
Example submission:
**Part 1 of 4:**
```
a2b3z5y6
```
**Part 2 of 4:**
```
ye7c93od
```
**Part 3 of 4:**
```
q2d4g6z8
```
**Part 4 of 4:**
```
2345nhyt
```
  ## Hints
Exiftool is provided on Windows and Kali.
Sometimes seeing is believing. Sometimes you have to look deeper into the image file itself.

  ## System and Tool Credentials
  | system/tool                | username | password |
  |---------------------------|--------------|-----------|
  | Optimus (Windows 10)              | user     | tartans  |
  | Megatron (Kali)                             | user     | tartans  |






# Thanks for Logging Secrets
## Background
The token resides somewhere in captured network traffic. By using forensic tools to analyze the provided disk image, you can find everything you need to obtain the token.
## Getting Started
You may use either a Windows 10 or a SIFT workstation to complete this challenge. Both workstations have an identical secondary drive mounted named **Image** that contains a packet capture (`https_capture.pcapng`) and a disk image of a Windows 10 machine (`win10-image.001`). 
## Submission Format
The token is a 16-digit hexadecimal number wrapped in the standard President's Cup wrapper of the format `prescup{0123456789abcdef}`.
Example submission:
```
prescup{e1121b977dd3e039}
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| win10-forensics  | user  | tartans  |
| sift-forensics | user  |  tartans  |
",





# Spot the Super!
## Background
Your organization uses PostgreSQL as the back-end database supporting a
variety of services. For convenience, database administrators are allowed
to connect to the PostgreSQL server in superuser mode, in order to perform
various maintenance tasks.
Your security department is, however, concerned about malicious insiders
or an administrator's potentially compromised machine creating additional,
\"back-door\" accounts with superuser privileges. A Suricata-based intrusion
detection system (IDS) is currently deployed to monitor traffic entering
and leaving the datacenter hosting (among others) the PostgreSQL database
servers.
As one of your organization's Cyber Defense Analysts, you have been asked
to develop a new IDS rule which would issue an alert whenever a new database
account (a.k.a. role) is created with superuser privileges.
***NOTE***: For simplicity, you are *not* required to issue alerts when
superuser privileges are added to an *existing* database account!
## Getting Started
You are given access to a development VM named `sooper`. In your `Documents`
folder, you will find the following files:
  - `example.sql`: log of a PostgreSQL superuser session during which a subset
    of a table's columns are listed, a regular (non-superuser) account named
    `foo` is created, and a superuser privileged account (`abc`) is created.
  - `example.pcap`: a packet capture of the above-mentioned PostgreSQL session.
  - `example.rules`: a sample Suricata rule alerting whenever a superuser
    account connects to the database server.
  - `submit_rule`: a shell script used to assess and grade your Suricata rule,
    which issues up to five tokens, each worth 20% of the total challenge
    points.
***HINT***: You are encouraged to open `example.pcap` in Wireshark and study
the composition and structure of the various queries in order to fine-tune
your IDS rule! Also, you may wish to visit the following links for information
on how to write good content matching statements as part of a Suricata/Snort
IDS rule:
  - [Suricata payload keywords](https://suricata.readthedocs.io/en/suricata-5.0.3/rules/payload-keywords.html)
  - [Keywords: offset/depth/distance/within](https://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html)
Develop your superuser account creation alert rule in a separate file
(named e.g., `super.rules`), and test it by running:
```
mkdir logs
sudo cp super.rules /etc/suricata/rules/suricata.rules
sudo suricata -r example.pcap -l logs
cat logs/fast.log
```
Examine alerts appended to `logs/fast.log` to test the functionality of your
rule. To have the system evaluate your rule (and hand out credit in the form
of tokens that can be submitted for points), run:
```
./submit_rule <your_rule_file>
```
You may do this as many times as necessary: your rule will be tested against
a number of different cases, and points will be deducted for missing actual
instances of superuser account creation, and also for alerting on instances
where a superuser account was ***not*** created (false positives). The maximum
number of tokens issued is 5, for a rule which alerts on all instances of
superuser account creation, and generates no false positives.
When you are satisfied with your results, submit all the tokens returned by
the submission script for credit.
## Submission Format
Submit up to five tokens returned by the grading script included on the
provided development VM (`sooper`).
Each token is worth 20% of the total.

Example submission:
**Part 1 of 5:**
```
OGM5MTBkNW
```
**Part 2 of 5:**
```
NDFhM2FkMD
```
**Part 3 of 5:**
```
NjIwMGM0ND
```
**Part 4 of 5:**
```
NDg5MTRjZW
```
**Part 4 of 5:**
```
NWIzYTBmM2
```
## System Credentials
| system      | username | password |
|-------------|----------|----------|
| sooper      | user     | tartans  |
",


