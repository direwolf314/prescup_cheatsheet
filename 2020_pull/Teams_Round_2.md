# World Wide Whoops
## Background
There are four vulnerable websites at IP address 192.168.1.10 on ports 5001, 5002, 5003, and 5004.   The code for each website is provided on the Kali workstations. The provided code may be partially redacted.  
## Getting Started
Visit each website from inside the gamespace and attack it to receive the token.  
 __You must visit and attack the website from inside the game environment.__  
1. http://192.168.1.10:5001  
2. http://192.168.1.10:5002  
3. http://192.168.1.10:5003  
4. http://192.168.1.10:5004  
Note: Several Python3 libraries are installed on the system (e.g. Requests) that may be helpful in solving this challenge. 
## Submission Format
There are 4 parts to the submission - 1 part for each vulnerable website.   The submission for each part will be a 16 character alphanumeric string (all lowercase).  See the list below for specific instructions for each website's submission. 
**Part 1 of 4:**  
http://192.168.1.10:5001 - The token will be displayed on the webpage when the required condition is met.
```
a1b2c3d4e5f6g7h8
```
**Part 2 of 4:**  
http://192.168.1.10:5002 - The token will be displayed on the webpage upon successful exploit of the vulnerability.
```
cowahrahyie4quag
```
**Part 3 of 4:**  
http://192.168.1.10:5003 - The token file will be downloaded from the server upon successful exploit of the vulnerability.
```
rae7eeku7jiemo3o
```
**Part 4 of 4:**  
http://192.168.1.10:5004 - The token to submit is the password for the user `admin`.
```
ohd7shoereequief
```
  ## System and Tool Credentials
  | system/tool | username | password |
  |-------------|----------|----------|
  | webmasterhacker | user     | tartans  |


> Download Resources: [PDF File](https://files-presidentscup.cisa.gov/t23-ResearchPapers.pdf) | [ISO File 46.9MB](https://files-presidentscup.cisa.gov/t23-3wnr0hnx-v4.iso)
# Transmission Control Problems 
## Background
You are attempting to diagnose several network situations by looking at packet captures. The situations are described below:  
**SYN Flood** - A SYN Flood occurs when an attacker takes advantage of the TCP 3-way handshake by sending a large number of SYN packets to a victim in an attempt to overwhelm the system's resources [1]
**Port Scan** - A port scan occurs when an attacker sends packets to a selection of ports on a host to determine which ports are open [2]
**Shrew Attack** - The Shrew attack is a low-rate Reduction of Quality attack which takes advantage of the congestion control mechanisms TCP has in place [3]
**Unencrypted Traffic** - Several TCP protocols send unencrypted data. By sending data \"in the clear\ the data in the packets is subject to being sniffed/analyzed by other nodes on the network. 
Research papers which discuss the first three of the above scenarios are referenced below and are attached to this challenge in one combined PDF. 
## Getting Started
In the CD drive of the Kali VM is the zip file containing the challenge pcaps. Unzip the files by using the `unzip` command. 
Each pcap is titled with the name of the attack to look for in that file. You should only be looking for the indicated type of network activity. 
In the file titled `synflood.pcapng` you should be looking to find the IP address of the node performing the SYN Flood as described above and in [1].
In the file titled `nmap_scan.pcapng` you should be looking to find the IP address of the node performing a port scan as described above and in [2].
In the file titled `shrew_attack.pcapng` you should be looking to find the IP address of the node performing a Shrew Attack as described above and in [3]. In this file, the IP address performing the attack does not have any other benign traffic (i.e. that node is only performing the attack).
In the file titled `telnet.pcapng` you should be looking for the password to the telnet server.
## Submission Format
The tokens you submit will be the IP address of the node performing the indicated network activity. There are four (4) submission parts as follows:
1. The IP address of the node performing a SYN flood attack
2. The IP address of the node performing a port scan
3. The IP address of the node performing a Shrew attack
4. The password for the telnet service (16 character alphanumeric string)
Example submission:
**Part 1 of 4:**
```
1.2.3.4
```
**Part 2 of 4:**
```
2.3.4.5
```
**Part 3 of 4:**
```
3.4.5.6
```
**Part 4 of 4:**
```
abcd1234efgh5678
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Exploiter   | user     | tartans  |

## References:  
[1] Haris, S. H. C., R. B. Ahmad, and M. A. H. A. Ghani. \"Detecting TCP SYN flood attack based on anomaly detection.\" 2010 Second International Conference on Network Applications, Protocols and Services. IEEE, 2010.
[2] Gadge, Jayant, and Anish Anand Patil. \"Port scan detection.\" 2008 16th IEEE International Conference on Networks. IEEE, 2008.
[3] Kuzmanovic, Aleksandar, and Edward W. Knightly. \"Low-rate TCP-targeted denial of service attacks: the shrew vs. the mice and elephants.\" Proceedings of the 2003 conference on Applications, technologies, architectures, and protocols for computer communications. 2003.



# Dissecting an Apple
## Background
You are provided with a forensic image. Your task is to use the tools available to you to analyze the image and answer the following questions.
## Getting Started
The `EVIDENCE` drive containing the forensic image (`image.dd`) is attached to the Analyst VM.

Your goal is to answer the following questions - 
1. The laptop owner met his friend at an Indian restaurant. When (in UTC) did they meet?
2. Which Indian restaurant did they meet at?
3. Which city is the laptop owner likely located in? 
4. Which browser was used to download `Honey comb shelves.jpeg` file?
5. Name the 3rd to last application used on the laptop.
6. Provide the `NX Block Number` of the APFS container present in the image. 
## Submission Format
Example submissions in order of questions:
**Part 1 of 6:**
```
Dec 19 2020 1930 UTC
```
**Part 2 of 6:**
```
Chipotle
```
**Part 3 of 6:**
```
Boston
```
**Part 4 of 6:**
```
Firefox
```
**Part 5 of 6:**
```
Contacts
```
**Part 6 of 6:**
```
1234
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Analyst  | user     | tartans  |


# Git Outta Here
## Background
Software developers often place sensitive information into source code and configuration files. This can lead to
the compromise of the application under development as well as other critical assets. As part of an incident response,
your team has discovered a git repository available to anyone on the network. Your task is to assess the repository
to determine if the programmer potentially leaked any sensitive data.
## Getting Started
Browse to the local GitLab instance at http://gitlab.lcl/kowalski. The GitLab service takes some time to start up, so
you may get a 502 error at first. It should be up and running after about five minutes. Using the tools at your disposal,
gather evidence that the developer negligently included privileged information in his project repository that would
allow an insider threat to access sensitive customer records. You are specifically looking for a password associated with the host `indb1.lcl`.
## Submission Format
The submission for this challenge is an 8-byte 16-digit hexadecimal string.
Example submission:
```
d0d0caca1337beef
```
## System Credentials
| system      | username | password |
|-------------|----------|----------|
| kali        | user     | tartans  |



> Download Resources: [ISO File 1.31GB](https://files-presidentscup.cisa.gov/t22-tu7wc11e.iso)
# In one ear and out the other
## Background
\t
You and your team are consultants that provide forensic analysis services. You have been called in from a customer organization that had recently encountered a network breach and data leak. You will not have access to live systems, only memory images and network traces that have been collected by initial incident response teams. However, you find that the memory artifacts were collected from only a server on the network and the packet capture had only been collected from the network's firewall. 
Reports from the incident response team indicated that the attacker had used a couple of methods to try and mask movements both on the network and locally on the compromised server. The attacker was also able to evade data loss prevention systems by using unconventional protocols, alternate transmission timing and data obfuscation techniques. 
Furthermore, the server administrator indicated that the server had contained several sensitive files including files with financial information for both employees and customers, a file with usernames and passwords and a file with contact information. The server administrator admitted that these findings had been reported in a recent vulnerability assessment, but were not taken into consideration since the server was protected by a firewall. 

## Getting Started
To start, you are provided two identical Windows 10 analysis workstations that you will use to complete the challenge. The computer's DVD drive contains the artifacts collected from the incident which consist of a memory dump and a packet capture.  Using tools like Volatility and Wireshark will help you answer the questions provided below. 
Based on the artifacts you will be asked a series of questions that will prompt you to investigate various parts of each artifact and in some cases correlate information between artifacts. This is a multipart challenge where scores will be assessed based on the number of correct answers.
### Questions
1. What IP address did the attacker send data too? Answer will be in standard IPv4 format (e.g., 1.1.1.1)
2. What is the name of the file that was exfiltrated from the victim machine? Answer will be in `filename.ext` format
3.  Following the initial transaction, what was the chunk size of packet data (in bytes) that was being exfiltrated by the attacker malware? Correct answers reflect the \"byte size of the data chunks\"  per packet and nothing else (i.e., padding or offset) 
4. What port is the attacker using to pivot into the victim machine? Answer format will be a port number (e.g., 1234)
5. What is the first listed physical offset of the initial exploit? (e.g., 0x12345abcd).
## Submission Format
Example submission:
**Part 1 of 5:**
```
1.1.1.1
```
**Part 2 of 5:**
```
filename.ext
```
**Part 3 of 5:**
```
10
```
**Part 4 of 5:**
```
1234
```
**Part 5 of 5:**
```
0x12345abcd
```



> Download Resources: [ISO File 106KB](https://files-presidentscup.cisa.gov/t20-4m9n8b718.iso)
# Pay for your syns
## Getting started
For this challenge, you will be given  **three (3)** different challenge scripts. One encryption script written in Python, and two decryption scripts, one written in Java and the other in Bash. For each script, you will be given the source code and an output string that was generated by running certain argument(s) through that script.
Your task is to write the *opposite* type of script to what is provided in order to encrypt or decrypt the message. For example: if you are working on the Python encryption challenge, you must write the corresponding decryption script in Python and determine the decrypted string. You must complete this process for all three scripts for full credit.
The starting scripts are available on your `Code` machine via the attached CD (visible on the desktop) in a folder named \"Scripts\".  There is also a \"Readme\" file in the iso that accompanies the \"Scripts\" folder. The Readme provides initial strings for each script and other notes on how to submit your answers. The number of `Code` systems will scale to the number of members on your team so that you may work independently on the various parts of the challenge. Each system will be identical.
You should generate the resulting encrypted/decrypted string(s) to what was initially provided and run it back through the original script as verification. When the correct string is used, you should get back what you were provided with in the beginning. 
**For example:** For the Python encryption script and encrypted message string, you should write code to generate the corresponding decrypted message string. After running your decrypted message through the original encryption script, the result should be the original encrypted string. If your method does not produce the original string, you should recheck your work. For this part, your _decrypted_ input string will be your submission. 
The Readme file on the gamespace desktop gives the last 8 characters of the MD5 hash for each correct answer string. In order to check your answer's hash, run the command `md5sum <<< \"yourstringhere\"`. You must escape the '!' character when running the hash against your string.
## Submission Format
When entering your submissions, please enter them in the following format:
1. *strictly* what string was entered against the **Python** script
2. *strictly* what string was entered against the **Java** script
3. *strictly* what string was entered against the **Bash** script

Example submissions:
**Part 1 of 3:**
```
helloworld
```
**Part 2 of 3:**
```
123456789
```
**Part 3 of 3:**
```
a3f5h5 ()
```
NOTE: Include all characters entered except for the literal character '\\'
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| code        | user     | tartans  |



# The Enemy Within
## Background
You've intercepted a piece of probable malware from within a spam email. It does not match known signatures, but judging by the attack method, we don't believe it is sophisticated. Please examine it, and determine if it was trying to steal information, and if so, what information.
## Getting Started
In this challenge, you will use tools to analyze a piece of malware. The malware is contained on a mounted ISO, and you are given a virtual machine to conduct your analysis.
You should focus on dynamic analysis of the running malware instead of static analysis of its machine code.
## Submission Format
The flags for this challenge are wrapped 16-character hex strings.
Example submission:
**(Part 1 of 2)** Local flag
```
prescup{0123456789abcdef}
```
**(Part 2 of 2)** Remote flag
```
prescup{fedcba9876543210}
```
## Systems and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Analyst | user     | tartans  |



> Download Resources: [ISO File 1.80GB](https://files-presidentscup.cisa.gov/t15_2700522d46cdf8e8.iso)
# No Alarm Needed. Incidents Wake Me.
## Background
An incident has occurred on your network that supports government parks. This incident included a recently government-purchased Android smartphone and two park servers (each in production when they should have still been in dev). You have been given full authorization for the network/creds/devices to figure out what is going on (some console access is not available, don't let that stop you!). The servers, devices, and overall network should not have been live, especially with the data on them! It has been isolated for you to investigate.
## Getting Started
The 3 devices have been extracted from the government network and setup in a sandbox environment to resemble their networked state during the incident in the 192.168.0.0/24 subnet.
Android - .109
Fairview Resouces - .111
Yellowstone Wiki - .116
All three systems have been confirmed to be involved in the incident. Also, the .vmdk of the Android device and the packet capture of the incident (while on government network with other machines) are located on the attached ISO for analysis. The live Android has been modified by the user since the .vmdk was captured live via a remote means. The .vmdk was captured prior to seizing the device from the user; however, you now have the Android live (VM) and the .vmdk on the attached ISO.
Answer the questions below while investigating. The means to answer the questions can be found while investigating. You have full authorization to utilize any credentials/logins to perform this invasive incident response. You do not have console access to Fairview Resources nor Yellowstone Wiki.
## Notes
The incident occurred around 19 June 2020.
The Android is set to 30-min display timer. If it blacks out on you, send a CTRL-ALT-DEL and/or reboot the machine.

RECOMMENDED: Unzip the .vmdk and .pcap on Kali first. This may take 2-3 minutes.
## Questions
1. What is the first name of the contact that appears to be an imposter of Fairview.gov?
2. What is the last name of the contact that was recently deleted from the Android device, but was captured in the .vmdk image?
3. What is the username of the login for MediaWiki found on Android? (HINT: Consider exporting all data from the contacts database or manually viewing the data live on Android)
4. What is the Xth value of the .txt/.csv that was download AND deleted from the Android device, but captured in the .vmdk image? Find the value by viewing the same-named file on MediaWiki. The specific value can be found above the answer submission text box.
5. There is an encrypted file and password/key somewhere separately. You might need to \"find creds\". Find them, use them, decrypt the file, enter the Xth value of the file. The specific value can be found above the answer submission text box.
## Submission Format
Enter the tokens in the correct box
Example submission:
**Part 1 of 5:**
```
Jane
```
**Part 2 of 5:**
```
Smith
```
**Part 3 of 5:**
```
bsmith
```
**Part 4 of 5:**
```
0123456789012345
```
**Part 5 of 5:**
```
word
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Android  | user     | tartans  |
| Kali  | user     | tartans  |



# 2 Boxes 4 Shells - II
## Background
A token is located in a user directory (/home/[UserID]/) and the root directory (/root/) of 2 boxes. Gather all 4 tokens only if ... you're elite
This challenge is completely unique and no advantage is given to challengers that successfully completed last round's 2 Boxes 4 Shells.
## Getting Started
2 rogue boxes are located on the 192.168.86.0/24 network, specifically between .200-.254. Box 1 is the lower IP address and Box 2 is the higher. Identify the 2 boxes' IPs in /24 network, scan hosts identified, access, analyze, exploit, and grab as many tokens as you can.
_Note: 192.168.86.2 is a DHCP server that can be ignored_
## Submission Format
Enter the tokens in the correct box
Example submission:
**(Part 1 of 4)** Box 1 User token
```
Words Found
```
**(Part 2 of 4)** Box 1 Root token
```
Words Found
```
**(Part 3 of 4)** Box 2 User token
```
Words Found
```
**(Part 4 of 4)** Box 2 Root token
```
Words Found
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| 1B4S-II-Kali#  | user     | tartans  |


# Pwning PowerShell
## Background
PowerShell is a powerful task-based command line shell and scripting language that allows for the rapid automation and execution of tasks that manage operating systems and processes. Multiple offensive security frameworks exist that are specifically designed to exploit PowerShell's ability to perform a wide range of administrative tasks. One such framework is **PowerSploit**. You must utilize the built-in scripts and modules of PowerSploit to obtain six total tokens spread across four different Windows 10 hosts.
## Getting Started
There are four Windows 10 hosts, three of which you have desktop access to. Use the following instructions/system information to obtain as many tokens as you can! 
*Hint: don't forget about PowerShell's built-in `Get-Help` cmdlet.*
### ScriptMod
Important System Information:
- 2 tokens (5% each)
- User-level privileges by default
- Windows Defender disabled
- PowerSploit module preinstalled at `C:\\Program Files\\WindowsPowerShell\\Modules\\PowerSploit`
There are two files located in the  `C:\\Users\\flare\\Documents` directory : 
- `encoded-script.txt`
-`encrypted-script.ps1`
When properly utilized, each file will produce a token. Starting with `encoded-script.txt`, use PowerSploit cmlets or any other known means to print each token to the console. Pay special attention to the VM name to help you determine a starting point.

### PrivEsc
Important System Information:
- 1 token (25%)
- User-level privileges by default
- Windows Defender disabled
- PowerSploit module preinstalled at `C:\\Program Files\\WindowsPowerShell\\Modules\\PowerSploit`
There is a permission-restricted file located at `C:\\Users\\admin\\Documents\\token.txt`. Use PowerSploit cmlets or any other known means to escalate your privileges and view the contents of the file. Pay special attention to the VM name to help you determine a starting point. 
*Hint: you may come across `w1bscntrl.dll`as a possible privilege escalation vector; it is recommended that you explore other possibilities.*
### CodeExec
Important System Information:
- 1 token (25%)
- User-level privileges by default
- Windows Defender **enabled**
- PowerSploit module preinstalled at `C:\\Program Files\\WindowsPowerShell\\Modules\\PowerSploit`
There is file located at `C:\\Users\\flare\\Documents\\shellcode.txt` that contains a PowerShell payload. Use PowerSploit cmlets or any other known means to execute the payload and print the token to the console. Pay special attention to the VM name to help you determine a starting point. 
*Hint: don't forget that Windows Defender/AMSI is still enabled.*
### Hidden
Important System Information:
- 2 tokens (5% and 35% respectively)
- Admin-level privileges by default
- Windows Defender **enabled**
- PowerSploit module **not** available locally 
The final machine is hidden from viewing. You must utilize PowerSploit or other known means to find and log on to the machine. The first simple token can be viewed at `C:\\Users\\flare\\Documents\\token.txt`. For the final token submission, find the NTLM hash of the user, ***Scotty***.
*Hints:* 
- *Don't forget that Windows Defender/AMSI is still enabled.*
- *All competition machines have Python preinstalled. Python has a lightweight HTTP server built-in.*

## Submission Format
Each system contains 1-2 tokens of varying weights. If you correctly execute the given task(s) on that system, the tokens will be printed to the console or viewable by other means.
The first five tokens are 16-digit hexadecimal numbers wrapped in the standard President's Cup wrapper of the format `prescup{0123456789abcdef}`.
The final and most heavily weighted submission is in the format of an NTLM hash of a specified user.
Please ensure that you supply each token in the correct box as labeled.
**Part 1 of 6:**
```
prescup{8839fc673d695cd4}
```
**Part 2 of 6:**
```
prescup{d3b0b23b6727ae6e}
```
**Part 3 of 6:**
```
prescup{d55d1ca148250d86}
```
**Part 4 of 6:**
```
prescup{96978953acdb27bd}
```
**Part 5 of 6:**
```
prescup{3662485261df1a66}
```
**Part 6 of 6:**
```
8564c4a3f21ab63982d7e1064d9371d3
```

## System and Tool Credentials
| system/tool | username | group | password |
|-------------|----------|----------|----------|
| ScriptMod  | user     | Users | tartans  |
| PrivEsc | user     | Users |  tartans  |
| CodeExec | user     | Users |  tartans  |
| Hidden  | user     | Administrators |  tartans  |


> Download Resources: [ISO File 16.8MB](https://files-presidentscup.cisa.gov/t17-EE6gjP5bqz.pcap.iso)
# Vlad the Inhaler
## Background
Multiple users are simultaneously connected to a VPN server, appearing to access Internet resources from the VPN's IPv4 address pool. You are provided with a packet capture taken at the VPN operator's upstream ISP, containing both encrypted tunnel traffic (between clients and the server), as well as cleartext (between the server's address pool and the Internet at large). Your job is to identify the IPv4 address of the client who used the VPN to download an image of \"Vlad the Inhaler\" (*Hint: search `images.google.com` for a visual clue*).
***NOTE***: The IPv4 address of the VPN server is `12.0.0.54`, and each VPN client is allocated a pool addresses from the `128.2.149.0/24` range.
## Getting Started
In the CD drive of your VMs is a PCAP taken during the attack period. You must identify the IPv4 address of the VPN user who downloaded an image file representing \"Vlad the Inhaler\".
***NOTE***: this is ***not*** the pool address allocated by the VPN service (in the 128.2.149.0/24 range), but rather the end-client-side IP address used to originate the VPN connection!
You can use the provided VM or download the ISO file to complete the challenge.
## Submission Format
The answer to the challenge is the **IPv4 address** of the client originating the VPN tunnel through which the image was downloaded.
Example submission:
```
192.168.152.13
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| stoker      | user     | tartans  |



# Build a Fortress
## Background
Rupt Bank got hacked recently. It's no wonder they did. Look at their network topology. No network segmentation or monitoring, all traffic is allowed inbound/outbound, use of public IP space for all systems, use of legacy systems - to list a few issues in their infrastructure.
![existing-topology](https://files-presidentscup.cisa.gov/img/t11-existing-topology.png)
## Getting Started
You are a group of Infrastructure Support Specialists called in to configure the new systems and rebuild their network from scratch using the following topology map. Your CISO is an open source evangelist. As such, you are provided access to a pfSense firewall, VyOS router, Security Onion IDS, Ubuntu Server for installing and configuring Squid proxy, and a Kali machine for testing purposes.

![proposed-topology](https://files-presidentscup.cisa.gov/img/t11-proposed-topology.png)
Please note that all systems in the network are at their default vanilla state with nothing configured on them except -
- On Security Onion, the management IP address is configured and the other three interfaces are assigned for sniffing.
- The web login for pfSense is changed to Username: `user`, Password: `tartans`
Your end goal is to determine and implement the configurations in the network that will allow you to pass the following three grading checks. Overall these grading checks/tasks enforce the defense-in-depth methodology.
| Grading Check | Grading Check Description | Weight |
|-------------|----------|----------|
| 1 | - Only HTTP traffic is allowed outbound <br> -  No traffic is allowed inbound <br> -  Outbound NAT is configured to translate traffic leaving the internal network to the IP address of the WAN interface of the firewall | 40% |
| 2 | A functional squid web proxy | 35% |
| 3 | Snort is configured to alert on any non-HTTP traffic originating from Users Subnet and is destined for the internet | 25% |
A grading script is executed every 5 minutes and the results are published to `http://150.37.91.102`.
Things to keep in mind ?
- The underlying networking (layer 1 and layer 2) is in place. The network adapters for all the systems are connected to the proper/correct networks.
- Use the IP address scheme as defined on the network map.
- The first phase of Security Onion setup is already done for you. This includes configuring the management interface IP address, and assigning the remaining three as sniffing interfaces.
- The Squid Debian package is mounted as an ISO to the Proxy system.
- Make sure the Squid web proxy is listening on its default port.
- Grading Server IP address can be used as the upstream gateway for the firewall.
- A Kali (Test) system is available for testing the configuration. It has an interface in all 5 subnets. The IP address that can be used for each interface is mentioned on the network topology map.
- The grading results URL (`http://150.37.91.102`) is accessible from 150.37.91.101 (Firewall) and 150.37.91.99 (Test system) only.
**Please note: Do *NOT* configure bridging on any of the systems as that will result in losing access to the VMs and the Gamespace. You will not be able to restart/relaunch this challenge and 0 points will be allotted for this challenge to your team.**
## Submission Format
The answer to each grading check is a code (string of random characters)
Example submission:
**Grading Check 1:**
```
nqr3i9sl
```
**Grading Check 2:**
```
iexu6aiz
```
**Grading Check 3:**
```
ere5aiku
```

## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Firewall Web Console  | user     | tartans  |
| Router    | user    | tartans |
| IDS       | user     | tartans  |
| Proxy   |   user    |  tartans  |
| Test     |   user    |   tartans |





