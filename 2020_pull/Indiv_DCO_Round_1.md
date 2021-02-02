> Download Resources: [ISO File 1.2MB](https://files-presidentscup.cisa.gov/a01-c472078a0007fa08.iso)
# Cooking and Cracking Codes
## Background
You work for a three-letter agency and have been given six files to decode. Each file relates to a question your agency needs to answer, as these files are relevant to an investigation. If you solve these, you will have helped keep the streets of your town cleaner from cyber criminals.
## Getting Started
The six files are in a zip on the attached ISO. This ISO is mounted to all gamespace virtual machines and is available for download from this page.
Answer the questions below as you decode the files related to the alleged perpetrator. CyberChef is a tool that you may choose to use; however, other techniques and skills will be required. CyberChef is currently installed on Windows 10 and Security Onion. It is highly encouraged to use Windows' CyberChef, as it is the newer version (hint hint). Other VMs are provided to allow for various methods of solution.
## CyberChef In-Game Browser Access
Windows: C:/User/flare/Programs/CyberChef/CyberChef_v9.20.3.html
SecurityOnion (shortcut on Desktop): localhost/cyberchef/cyberchef.htm (accept warning by clicking Advanced -> Proceed to localhost)
## Submission Format
Enter the answer in the correct box.
Example submissions in order of questions:
**Part 1**
```
which
```
**Part 2**
```
636
```
**Part 3**
```
987
```
**Part 4**
```
abc
```
**Part 5**
```
001011110
```
**Part 6**
```
noun
```
## Questions
1. Regarding 1.txt, your team found this script on an attacked machine. What command were the attackers trying to run?
2. Regarding 2.txt, your team found another script that was being launched on startup. Decode the script, don?t be fooled by running it. How many /dev/urandom (not /dev/random) lines are overwriting the bash history in this command?
3. Regarding 3.txt, decode and find out what the secret number is. What is the secret number?
4. Regarding 4.txt, what three letters must be echoed, instead of the five letters, to print the current working directory?
5. Regarding 5.txt, your boss believes this data possesses an XOR algorithm that provides a needed 8-bit key. What is the 8-bit key?
6. Regarding 6.txt, this file was found on a suspected attacker?s machine. It was found alongside an encrypted journal and other personal thoughts. Find the flag within the data as it may help your agency decrypt the journal. The flag is only one word! Read everything!
## System and Tool Credentials
| system/tool    | username | password |
|----------------|----------|----------|
| Kali           | user     | tartans  |
| Windows 10     | user     | tartans  |
| Security Onion | user     | tartans  |
| SIFT           | user     | tartans  |





> Download Resources: [ISO File 548KB](https://files-presidentscup.cisa.gov/a05-DFZJx3wLDZ.iso)
# Dunning & Kruger Netflow Inc.
## Background
In light of the recent push to allow remote work, Dunning & Kruger, Inc. has allocated a publicly routable IP network to their user workstations. They have enabled remote SSH access since the majority of employees are now connecting from home. The user LAN has been allocated addresses within 168.192.0.0/24.
D&K also allocates non-routable (RFC1918) space for its datacenter machines in the 192.168.0.0/24 range.
The network is monitored via IDS, and Netflow records are collected to support incident response activities whenever necessary.
An IDS alert was received indicating possible unauthorized access to one of the database servers connected to the D&K datacenter network.
One of D&K's database administrators is known to have legitimately accessed the same server during roughly same time window.
So far, it has been established that the attacker ran a ping scan of the user network, followed by a Hydra SSH brute-force attack against any machines that responded to pings. Once successfully compromised, a user workstation was used to access the database server on the internal datacenter network.
You are presented with an nfcapd file representing NetFlow records saved during the time frame of the incident. You are tasked with conducting an initial assessment of the situation.
## Getting Started
In the DVD drive of your VM is an nfcapd file containing Netflow data collected from D&K's router. Familiarize yourself with the `nfdump` command line tool (using any other Netflow analysis tool is allowed). You may use the provided VM or download the `nfcapd` file for offline analysis.
Finally, please note that, internally, Netflow records in an `nfcapd` file use UTC timestamps, but that the `nfdump` utility automatically converts them to ***local*** time (as configured on the underlying machine) during
output. You are expected to provide timestamps in `US/Eastern (EDT)` format.
On Linux, you can confirm this by issuing the `timedatectl` command. To set
the appropriate time zone, run:
```
sudo timedatectl set-timezone 'US/Eastern'
```
## For credit, answer the following questions:
1. What is the attacker's (external) IP address?
2. What is the legitimate administrator's (external) IP address?
3. What is the IP address and port number of the D&K database server (on the datacenter network)?
4. When does the Hydra SSH brute-force attack (incl. initial SYN scans of tcp/22) start and end?
5. What is the duration of the longest successful TCP attacker-initiated session between the compromised D&K user-LAN IP and the D&K datacenter machine?
## Submission Format
For questions that require an IP address (e.g., 1, 2), provide the
IPv4 address of the applicable machine (e.g., `192.168.148.23`).
If the question inquires about an IP address ***and*** port number
(e.g., 3), append the latter to the former with a semicolon separator
(e.g., `192.168.148.23:8080`).
Questions asking about the start and end time(stamp) of a given event
or activity (e.g., 4) expect a pair of comma-separated `US/Eastern`
timestamps formated as `hh:mm:ss.mmm` -- hour, minute, second, milliseconds.
An example might look like `09:30:45.012,17:01:20.789`, and represent a
time interval spanning roughly from half past 9am to a bit after 5pm.
Finally, questions regarding the duration of a specific event should be
answered by providing the number of seconds and milliseconds (e.g., `12.345`).
Example Submission:
| Q | A                           |
|---|-----------------------------|
| 1 | `192.168.148.23`            |
| 2 | `192.168.148.24`            |
| 3 | `192.168.148.26:8080`       |
| 4 | `11:30:45.012,12:01:20.789` |
| 5 | `44.345`                    |
### Systems and Tool Credentials
| system  | username | password |
|---------|----------|----------|
| cluebat | user     | tartans  |






# Stratification Preformation
## Background
In this challenge you are provided a series of files, that have been extracted from a recent cyber security incident. Your objective is to write YARA rules to find three files containing different indicators of compromise. 
## Getting Started
To start, you will login to the Windows 10 workstation (WIN10-YARA) that you will use to complete the challenge. The computer's DVD drive contains three folders, each with a library of files extracted from a recent investigation. The folders correspond to each IOC that you will target with your YARA rules. On the virtual machine, you will also find that YARA has been installed at C:\\tools\\yara\\. In this folder, an example rule is provided to serve as a reference for rule syntax. Once your rule is created, you can run a scan by referencing it as a parameter with yara64.exe. Additionally, you will find that the threat actor who created the files also placed in some obfuscation techniques to obscure commands in each file. Each folder on the disk corresponds with IOCs listed in the table below.
## Indicators of Compromise
| folder       | IOC                                                        |
|--------------|------------------------------------------------------------|
| /IP          | 164.240.138.239                                            |
| /DNS         | hvOiwETMXmzgAfcGrqlHUCQIyVDBbpoJZdKYPensxruNtaLSjFkW.com   |
| /CODE        | rCvAfWxe.exe                                               |
## Submission Format
The answer to each part of this challenge is the **filename** that matches the indicated IOC.
Example submission:
**Part 1**
```
filename1.ext
```
**Part 2**
```
filename2.ext
```
**Part 3**
```
filename3.ext
```
## System and Tool Credentials
| system/tool | username  | password   |
|-------------|-----------|------------|
| Windows     | student   | tartans    |






> Download Resources: [ISO File 471.4MB](https://files-presidentscup.cisa.gov/a06-326y77zswl9vodcl.iso)
  # Packet out, packet in, let the incidents begin
## Background
Your network (10.9.8.0/24) has been attacked. You are provided access to several workstations and a network IDS as well as a full packet capture file. It is unknown whether the rules included have been tuned and/or baselined, and therefore some alerts may be benign.
## Getting Started
The packet capture file has been mounted to the DVD drive of all three systems within the challenge.
On DJ-Lethal, the Security Onion system, the packet capture has been copied to `/home/user` and has also been imported into the IDS tools at the start of the challenge using `so-import`. This populates the alerts to Sguil automatically (use the so-import sensor) and it may take a few minutes to entirely load the alerts.
Any system, or combination of systems, can be used to solve the challenge. This challenge can be solved entirely with the packet capture alone.  The IDS is included only as a reference and *will not* contain all of the data that you need in order to solve the challenge.
## Questions
1. Some files were transferred in this capture. Which system (IP address) received a file that might be used to perform further network reconnaissance? (20%)
2. Which system (IP address) receives the largest amount of data, in bytes, within this packet capture? (20%)
3. Which system initiated a port scan within the network (IP address)? (10%)
4. How many ports were found to be open/responsive on the scan target host and what is the value of the highest open port (numerical answers with a single space in between)? (25%)
5. What is the 8-character text string found within the shell script contained within the badstuff.zip file that was transferred in this packet capture? (25%)
  ## Submission Format
 Each answer for submission will either be in the form of an IP address, a set of numbers, or an 8-character text string. Each question includes a hint to the the expected submission type.
  Example submissions:
**Question 1**
```
192.168.10.25
```
**Question 2**
```
192.168.16.235
```
**Question 3**
```
192.168.17.190
```
**Question 4**
```
 3 8080
```
**Question 5**
```
1234abcd
```
## Hints
Wireshark filters and statistics will be very useful in this challenge. Not every alert is a legitimate incident and not every alert may be relevant. You may safely ignore all OSSEC alerts.

  ## System and Tool Credentials
  | system/tool                | username | password |
  |----------------------------|----------|----------|
  | Everlast (Windows 10)      | user     | tartans  |
  | DannyBoy (Kali)            | user     | tartans  |
  | DJ-Lethal (securityonion)  | user  | tartans  |
  | All Security Onion tools   | user     | tartans  |





# Memory Mayhem
## Background
You received a memory image from a victim machine that has initially been exploited using [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144). You must determine information about the offending process(es) involved in the attack.
## Getting Started
The image file is mounted to the DVD drive of each gamespace virtual machine. You may use all available forensic tools in either virtual machine to answer five (5) questions for the challenge.
## Questions
1. What is the name of the malicious configuration file that invoked an RDP process?
2. What is the IP address and port where the RDP exploit originated?
3. What is the LastWrite time in hours, minutes, and seconds of the USB thumb drive that was attached to the victim?s computer?
4. What is the first PID associated with the marketing.doc file found on the victim?s machine?
5. What is the first listed allocation address for the initial exploit that gained access to the victim?s machine?
## Submission Format
Enter each answer in the correct submission box.
Example submissions in order of questions:
**Question 1**
```
test.cfg
```
**Question 2**
```
10.1.10.1:443
```
**Question 3**
```
01:02:03
```
**Question 4**
```
123
```
**Question 5**
```
11k12l13m14
```

## System and Tool Credentials
| system/tool                     | username | password |
|------------------------------|---------------|--------------|
| WinTheDay (Win 10)    |    user          |   tartans     |
| Linux4Life (Kali)            |    user          |    tartans    |




