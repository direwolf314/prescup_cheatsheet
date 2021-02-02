# Reverse Engineering Joy Ride
## Background
You should understand how a program interacts with a dynamically-linked library (DLL). This includes viewing what functions the program is using from a DLL. You should determine how a
Microsoft API function works from [the documentation](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexa).
Finally, you should understand the concept of hooking to intercept (and log) a function's
arguments.
## Getting Started
You should see a mounted DVD attached to your Windows VM. It contains the challenge executable file as well as a zipped folder with a trimmed-down copy of the official Detours repository. The Detours library is already compiled for you. Extract this folder to the Desktop, as it will be important for this challenge.
The folder structure includes the simplest example in the Detours repository for convenience. Feel free to go examine
the [full Detours repository on GitHub](https://github.com/microsoft/Detours), but there is more information than you'll need for this challenge.
There is client/communication in this challenge. Given that, you should
run the client (`prescup-t7-r1.exe`) and examine the generated traffic in Wireshark. Consider why the traffic looks this way.
Next, determine if the program is using any Microsoft API functions that explain this network traffic. IDA or another similar tool can give you this information. The program uses some Microsoft API functions, and you should identify more than one. Have a look at the Microsoft documentation for all of the functions you find, paying special attention to function arguments.
Now open the provided Detours folder and navigate to **\\Detours trimmed\\samples\\prescup**. Open `prescup.cpp` in whatever
editor you like. In this file, you will define hooks for the functions you found. Analyze
**\\Detours trimmed\\samples\\simple\\simple.cpp** for an example of this being done with another function.
Once you're ready to compile your DLL, open the Start menu and do a search for
\"x64 Native Tools Command Prompt for VS 2019\". Open it and navigate it to your **\\Detours trimmed\\samples\\prescup**
folder, and then type `nmake`. Assuming your code is written correctly, it will compile and create a new
`prescup64.dll` in **\\Detours trimmed\\bin.X64**.
Open a separate, non-developer, Powershell or Command Prompt window and navigate to the **bin.X64** folder. Enter
    .\\withdll.exe /d:prescup64.dll C:\\Path\\To\\prescup-t7-r1.exe
(entering the actual path to the challenge
executable). Once the process finishes, there will be a `prescup.log` in this folder, assuming that you used the
provided `Log()` stream in `prescup.cpp`.
## Submission Format
In `prescup.log` will be the output that you dumped during the challenge. Assuming that you've done everything
correctly, there will be two separate flags in this file. They will have the format `prescup{0123456789abcdef}`.
There will be one flag sent from the client to the server (Outgoing), and another flag that the client receives from the server (Incoming).
You should submit the string within the `prescup{}` wrapper, _not_ the wrapper itself.
Example submissions:
**(Part 1)** Outgoing token
```
0123456789abcdef
```
**(Part 2)** Incoming token
```
fedcba9876543210
```
## Systems and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| mercury-v2 | user     | tartans  |



> Download Resources: [PDF File](https://files-presidentscup.cisa.gov/t12_Threat_Intelligence_DG.pdf)
# Cyber Thimblerig
## Background
A recent outbreak of a new ransomware variant by a known threat actor has your organization's leadership team in panic mode. When news breaks of the first organizations hit by the ransomware, they ask your team to assess the risk to the organization and locate the vulnerable assets on your network. However, information on the variant is limited, so you will need to disseminate actionable steps from unstructured threat intelligence provided to you. Using this information and your Kali Linux assessment machines, determine which one of three machines is vulnerable to the attack. Your team will then need to extract a running file name from the machine to help provide indicator of compromise information back to the security community. The name of the malicious file will be the submission for this exercise.
## Getting Started
In the game Thimblerig, players are challenged to find a single object hidden underneath one of three cups. The cups, each turned upside down are shuffled to disorient the player and cause them to select a cup that does not contain the object, thus losing the game. Cyber Thimblerig operates on the same premise. To start this challenge, you are presented with threat intelligence information in an unstructured format, specifically in the form of blog posts, tweets and public reports. The information will be mostly devoid of indicators of compromise. Your objective is to use this information to determine which one of three target machines is susceptible to this attack. Once you've collected relevant information, you will need to survey, enumerate, and verify three machines to identify the vulnerable system. After that, you can remotely connect to it and extract an indicator of compromise in the form of a file name.
![topology](https://files-presidentscup.cisa.gov/img/t12_topology.png)
## Submission Format
The answer to the challenge is the **filename** which is running on the compromised machine.
Example submission:
```
filename.ext
```
## System and Tool Credentials
| system/tool | username | password   |
|-------------|----------|------------|
| Kali        | root     | tartans    |
| Windows     | user     | tartans    |
| OpenVas     | admin    | tartans    |



# Finding Footprints
## Background
Your organization's security team has found rogue systems within a cluster of Windows 10 computers in their network.
The number of rogue machines is unknown as different IP?s randomly appear and disappear. Also, they seem to be running an operating
system different than your standard build. Additionally, analysts have noticed encrypted
traffic between some machines.
Four staff members were interviewed for suspicious activity. They won?t reveal who
is working with them on the outside, nor what their plan is. Their machines have been removed from the network and you must analyze their machines to determine who else is involved, who/what they are targeting, and when they plan to execute their attack.
## Getting started
You have access to live images of the four suspect machines. You must determine:
-   The name of the person who is the external threat
-   The name of the person they are targeting
-   IP address of the target machine
-   The date of the planned attack
## Submission Format
When entering your submissions, please enter them in the following format:
-   Initials of External Threat
-   Initials of Internal Target
-   IP targeted
-   Date attack was going to take place (MM/DD/YYYY, there are no leading zeroes)
Example submissions:
```
HP
```
```
LS
```
```
123.456.78.90
```
```
1/11/1111
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Hans        | user     | tartans  |
| Karl        | user     | tartans  |
| Theo        | user     | tartans  |
| Eddie       | user     | tartans  |



# More than Meets the Eye
## Getting Started
On the desktop, you will see a folder called \"Challenge.\" Inside of this folder, there is a script called _run&#46;sh_. This runs the program you are analyzing. You may execute it with either `sudo ./run.sh` or by simply typing `run`. Inside the _src_ subfolder is the Java source code to examine.
The program allows the user to search for statistics on players from the four major sports, as well as compare the statistics of two players. When you run the program, you will see a drop-down menu and three text boxes. To search for an individual player's statistics, select the appropriate sport from the drop-down menu, type the player's name into the leftmost text box, and press search. To compare two players, select the appropriate sport, type the players' names into the two rightmost text boxes, and press compare.
Your job is to, by examining the source code of the program, determine what hidden functionalities exist and how to trigger them. Doing so will produce flags.
## Winning Conditions
There are 4 flags, each worth a percentage of the total possible points. As such, all four must be found and submitted to receive full credit.
## Submission Guidelines
Flags are a 12 character sequence of lowercase letters and numbers.
Example submission (all parts):
```
ubv13x6j9dh4
```
## System and Tool Credentials
| system/tool      | username | password |
|------------------|----------|----------|
| Kali-T10         | user     | tartans  |



> Download Resources: [ISO File 920KB](https://files-presidentscup.cisa.gov/t02-c7oGCnQmCr.iso)

# Allie, Bubba, and the 40 Bad Bitcoin
## Background
Allie, Bubba, Chuck, and DeeDee have all sent approximately 40 BTC to
Koinbase, an exchange service that happens to be subject to the type
of \"Know your customers\" legislation that requires it to refer suspect
activity to law enforcement for further review.
Our four customers all want Koinbase to exchange their Bitcoin for USD.
Following a subpoena issued as part of a US Government investigation,
Koinbase has provided details of the transactions they placed on the
public blockchain on behalf of these four customers.
Your job is to determine which, if any, of the four customers' Bitcoin
may be connected to known illegal activity, and to flag suspicious
transactions for further review by various law enforcement organizations.
## Getting Started
Unpack the `handout.zip` file from the CD/DVD drive, which should yield
`data.md` (containing the public bitcoin addresses of Allie, Bubba, Chuck,
DeeDee, and Koinbase, as well as the transaction ID of the known illegal
ransomware payoff), a `regtest` folder containing the blockchain, and a
`btc_shell_alias` file containing a handy shortcut for easier invocation of
the `bitcoin-cli` command:
```
mkdir ~/.bitcoin
cd ~/.bitcoin
unzip /media/cdrom0/handout.zip
source btc_shell_alias
```

The challenge blockchain is meant to be used in `regtest` mode, as the real,
public (production) blockchain utilizes over 250GB of disk space.
Start `bitcoind` in a way that will not have it reach out to the network:
```
bitcoind -daemon -regtest -noconnect -reindex -txindex
```

Ensure that `bitcoind` is listening for ***local*** IPv4 client connections:
```
netstat -antp
...
tcp   0   0   127.0.0.1:18443   0.0.0.0:*   LISTEN   <some-pid>/bitcoind
...
```
Run
```
btcli -help [command]
```
for the list of available commands, and for details on any particular command (hint: you may find `getchaintips`, `getblock`, `getrawtransaction`, and `decoderawtransaction` of particular interest).
## For credit, answer the following questions:
1. (5%) Block ID (hash) of the active blockchain tip
2. (5%) Public address of the ransomware attacker
3. (60%) Transaction IDs (hashes) representing each user's deposit to Koinbase (15% for each TxID)
4. (30%) Each user's Koinbase deposit can be in one of the following situations:
  - a) coins part of ransomware payoff, received directly or indirectly from attacker
  - b) coins not part of ransomware payoff, but received from attacker (directly or through one or more intermediaries)
  - c) coins unrelated to either ransomware payoff or the attacker
<br><br>Identify the transaction ID that provides the funds (input) being turned over to Koinbase by a user who is *innocent* (i.e., for whom situation (c) above applies).
## Winning Conditions
Answer all four questions. Questions are independent of each other.
## Submission Guidelines
Answers should be either 64-character hex strings representing Bitcoin block and transaction IDs, or 35-character alphanumeric strings representing Bitcoin user public addresses.
Example:
| Q  | A                                                                  |
|----|--------------------------------------------------------------------|
| 1  | `49347fa63adc43f4ffb43ac7caa91d19cfe52093e61cae7450b769eb2844c6bb` |
| 2  | `2XBvVZb6LiGwUnN1ZtDUzhXV1Qh2kWNesUK`                              |
| 3A | `44bcb15c20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618744aa` |
| 3B | `973cfda05f4b85301e50f58dc16fcdbf6a9fcd3de25776c83adad61820573662` |
| 3C | `9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8` |
| 3D | `7b914d13e74920da576ab9e7e0f66fed99be0757495c6e9d5d40896a638864bd` |
| 4  | `53cbd26b20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618834db` |

### Systems and Tool Credentials
| system | username | password |
|--------|----------|----------|
| sesame | user     | tartans  |



# Spies Like Us
### Background
You are assisting federal law enforcement with an espionage investigation involving the suspected illegal sharing of highly classified information between a U.S. government contractor and a foreign intelligence service.
### Getting Started
Klaus Fuchs is a U.S. Government contractor suspected of exchanging classified material with a foreign intelligence service.  The FBI arrested Klaus Fuchs on espionage charges and imaged a suspicious virtual machine that Klaus used on his computer.  It is now up to you to locate the remaining information needed to further the investigation.
Klaus was last in contact with a foreign intelligence agent named Aldrich Ames, who provided Klaus with classified material stored within a hidden volume of a keyfile/password encrypted container named `Outdoor Pics.zip`. The keyfile to open `Outdoor Pics.zip` is within an encrypted container named `Vacation Pics.zip`.  You must decrypt the containers to access the classified material.
**NOTE:** The encrypted containers are available to you as separate evidence on the mounted DVD (D: drive) and are NOT part of the forensic image. Within the D: drive, you will also find instructions needed to decrypt the containers in `Gameboard-Description.pdf`. **Autopsy** and **Bulk Extractor** reports are already available within an `Image` folder on your VM Desktop to minimize the time it takes to analyze the forensic image. The forensic image for Klaus' computer is also present in the `Image` folder.
## Submission Format
Submissions should be entered as described in the gameboard description file found in the DVD drive (D:). The submission formats are varied depending upon the questions that are asked.
     Example submissions:
     Question 1: 123.45.67.89
     Question 2: 01:02:03
     Question 3: haveaniceday
     Question 4: #wintheday
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Analyst     |    user    |      tartans    |



# ConnectFour (but with IPv6)
## Background
Three systems have been hidden on your network. Each system available to you shares a network with one of these hidden systems. You must discover these systems on each of the three different systems/networks, find an open service, and make three unique connections. Once you have made all 3 connections, you will be able to assemble the password for a new user with elevated privileges. With this new user account, you can access a hidden system to further reconfigure a service to allow a new connection from a new user. The catch: these hidden systems only listen and respond over IPv6 and your systems have no current network configuration. You only have the following networking information and the various scanning and enumeration tools at your disposal.
## Getting Started
1. Perform network discovery from each system in order to discover the IPv6 address of the hidden system. Each team system will only find one hidden system out of the 3 total, one per network. These beacons will always come from an **2002:aaaa:bbbb:cccc:dddd:eeee:xxxx:xxxx** type address.
2. Configure the various team systems for their proper IPv6 addresses based on the following guidance. All addresses will have the form **2002:aaaa:bbbb:cccc:dddd:eeee:xxxx:xxxx** where you must find the proper values for the final two hextets.
   *- Configure Windows10-A*
   The system used to be set with an IPv6 configuration of 2002:aaaa:bbbb:cccc:dddd:eeee:0a64:0a19/126. This address is correct, but something else is wrong that will prevent your connection from going through.
   *- Configure Kali*
   Convert the IPv4 address of 172.16.60.198/30 to an IPv6 address where an IPv4 address of 10.100.25.50 would be 2002:aaaa:bbbb:cccc:dddd:eeee:0a64:1932 (simply converting the IPv4 octets to hex for the values of the final 2 hextets). You should use a IPv6 subnet mask that maintains the number of allowed hosts from the previous IPv4 value (i.e. /24 allows 256 hosts in IPv4?what mask also allows for 256 hosts when using IPv6).
   *- Configure Windows10-B*
   Find the hidden system's IPv6 address first. Then apply the first available host on the same subnet when applying a subnet mask of /115, i.e. the host that is furthest from the hidden system within that subnet. Sometimes this connection can take a while to return a command prompt after logging in.
3. Enumerate/scan each hidden system in order to find an open service to connect to. The hidden system will reject all attempts to connect over IPv4 and also reject attempts that are not coming from the specific IPv6 address or range of addresses expected.
  \tOn Windows10-A use **UserA/tartans** to connect.  
  \tOn Kali use **UserB/tartans** to connect.  
  \tOn Windows10-B use **UserC/tartans** to connect.  
4. Once connected from each system, look in the landing directory for an answer file and 1/3 of UserD?s password. You will not be able to browse to other directories with these user accounts or run restricted commands. Each of these answer files provides 1 out of 4 answers for the challenge.
5.\tUse one of the previous three methods to connect using UserD?s password. Only one will work.
6.\tUse this account to reconfigure the SSH service so that UserE can also connect from Windows10-A with its current address. You will have limited administrative privileges when using sudo and the password \"tartans\". If you cannot run a specific command it is not one that you need.
7.\tOnce connected as UserE via SSH, the final answer file will be found in the landing/home directory.
## Winning Conditions
In order to win the challenge, all steps above must be completed and the team must find all four answer files on the remote system. Each answer file is worth 25% of the overall point value for the challenge.
## Submission Format
Each submission is a 12 character string made up of numerals and lowercase letters. No lowercase L's are used, only numeral 1's, to avoid confusion between the two.
Example submission:
```
abcdef123456
```
## Hints
You may use online IP/subnet calculation tools and perform research for the proper scanning syntax.
Creating hosts file entries for the hidden systems will reduce typing and makes connections faster.
## System and Tool Credentials
| system/tool      | username | password |
|------------------|----------|----------|
| Windows10-A-t08  | user     | tartans  |
| Windows10-B-t08  | user     | tartans  |
| Kali             | user     | tartans  |



# 2 Boxes 4 Shells
## Background
A token is located in a user directory (`/home/[UserID]/`) and the root directory (`/root/`) of 2 boxes. Gather all 4 tokens only if you can.
## Getting Started
2 boxes are located on the **10.8.14.0/24** network. Box 1 is the lower IP address and Box 2 is the higher. Identify the 2 boxes' IPs in the /24 network, scan the hosts identified, identify how they can communicate with each other, exploit, and grab as many tokens as you can.
## Submission Format
Enter the tokens in the proper submission field.
Example submission:
**(Part 1)** Box 1 User token
```
WordInsideTextFile
```
**(Part 2)** Box 1 Root token
```
WordInsideTextFile
```
**(Part 3)** Box 2 User token
```
WordInsideTextFile
```
**(Part 4)** Box 2 Root token
```
WordInsideTextFile
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| 2B4S-Kali#  | user     | tartans  |



# Git 'R Done!
## Background
Software developers often place sensitive information into source code and configuration files. This can lead to
the compromise of the application under development as well as other critical assets. As part of an incident response,
your team has discovered a git repository available to anyone on the network. Your task is to assess the repository
to determine if the programmer potentially leaked any sensitive data.
## Getting Started
Browse to the local GitLab instance at http://gitlab.lcl/kowalski. The GitLab service takes some time to start up, so
you may get a 502 error at first. It should be up and running after about five minutes. Using the tools at your disposal,
gather evidence that proves the developer negligently included privileged information in his project repository. This may
allow a malicious insider to access sensitive customer records.
While browsing the repository, identify a software error that affects how data is stored in the database. Your success depends
on finding the bug and accessing the database. There is a single row in the database that has been affected by the bug in the code.
The token for this challenge will be derived from the last name saved in the affected row. You will be able to
identify it because it will be encoded with ROT13. For example, the element Arsenic would appear in the database as Nefravp. 
The
_decoded_ name will be your final submission.
## Submission Format
The submission for this challenge is a single English word describing a metallic element from the periodic table. The first
letter will be capitalized. _Do not_ submit the encoded string found within the challenge environment. Decode it using ROT13 before
submitting.
Example submission:
```
Arsenic
```
## System Credentials
| system      | username | password |
|-------------|----------|----------|
| kali        | user     | tartans  |



# Welcome to Traffic School
## Background
Your network firewalls were destroyed in a massive fire, and no configuration backups survived. To save money (and time), your team decided to install pfSense firewalls in their place. You must configure the necessary routing, port-forwarding, and firewall rules to meet a specific set of conditions. Otherwise, CHiPS, the Computer High-intensity Protection Services will be forced to shut down your network.
## Getting Started
You are provided with direct console access to both the external firewall, JB, and the internal firewall, Ponch. You also have access to two Windows test systems:
* **Bear** has its interfaces in both the _WAN_ and _Internal_ networks.
* **Grossie** has interfaces in the _Users_, _MGMT_, and _Services_ networks.
You may use these systems to test the various traffic types and access the firewall web consoles, but will need to configure IP addresses for them as necessary. **Avoid assigning IP addresses that end in 250 or above, as these belong to grading systems.**
Both of your firewalls come with the interfaces correctly  preconfigured, but you must configure the necessary routing, port-forwarding, and rulesets to meet the set of conditions that follow. Currently, ALL traffic is allowed.
A grading server exists in the WAN network at 192.168.1.250 and is accessible from Bear at challenge start. The site will also become available from Grossie once all FW conditions are met to allow web traffic to the WAN Net. This server's web page (http://192.168.1.250) will display your grading results as you complete the challenge. The grading site will also be used to test web connectivity from the internal network for grading purposes. The grading results page will refresh every minute, though grading scripts run every 5th minute and may take 1-2 minutes to complete. As grading checks run, grading data may temporarily be rewritten to the page.
___
Given the following network map image:
![Network Map](https://files-presidentscup.cisa.gov/img/t16-topology.png)
Ensure the following grading checks can be passed. Each check is worth 20% of the overall challenge score and will provide one  of four challenge tokens once the check is passed.
_Grading Check #1 - External Access_
1. Verifies that ICMP requests inbound are blocked.
2. Verifies that the DMZ web page is accessible at 192.168.1.1, which requires the proper port forwarding on JB.
_Grading Check #2 - Internal ICMP_
1. Verifies that the MGMT systems can ping Users, the SecurityOnion, and the DMZ web server.
2. Verifies that Users and the Service network cannot ping anything, including their own gateway.
_Grading Check #3 - Internal Web Access_
1. Verifies that Users within the DHCP range only and all MGMT systems can access **both** the DMZ web page at 10.0.1.10 and the external grading site at 192.168.1.250.
2. Verifies that the Service network cannot access this page.
_Grading Check #4  - Remote Access from MGMT_
1. Verifies that MGMT systems can access Users via RDP
2. Verifies that MGMT can access the SecurityOnion via SSH
3. Verifies that no other ports are open to connections on those systems via port scans.
If all 4 checks can be achieved simultaneously for one full grading cycle, then a 5th token will be generated to provide the final 20% of the challenge score.
Each grading requirement can be met individually, though the only way to achieve a full score for the challenge is to achieve all conditions simultaneously.
___
## Submission Format
The answer to each grading check is an 8-character alpha-numeric string
Example submission:
```
a1b2z5y6
```
Hints
1. The User Test System and SecurityOnion system may have local firewall rules that need to be modified as well. 
2. \"so-allow\" can enable analyst access to SecurityOnion.
3. Remember that traffic tests from the test systems may require you to temporarily change static routes or enable/disable other interfaces on the system to ensure traffic flows from the correct interface.
4. Think about the perceived source of ICMP requests going to the DMZ from MGMT. 
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Bear/Grossie    |   user    |   tartans |
| Firewall Web Console  | user     | tartans  |
| SecurityOnion and ssh login | user | tartans |
| User RDP login | user | tartans |


# Mission Identification
## Background
You work for a three-letter agency and have gone undercover to identify fraudulent business practices. You have successfully infiltrated the target organization, Blue Ridge Bets (BRB). Today is your first (and only) day at work, so do not worry about being too loud on the network as tomorrow you will be long gone.
Identify the correct subnet to attach to, enumerate the network, browse and access everything you can. Answer the questions that headquarters needs to know. It is recommended to have internet readily available out of game to assist with any technical hurdles you may face.
## Getting Started
Your computer has been attached to the corporate switch; however, no DHCP is available. You have arrived to work early and no support is available. All you know is the BRB network's subnet is 172.[16-31].4.0/24 and you may or may not be attached. Find the correct subnet, connect to it (if needed), and stay connected throughout. The last octet of .91-.95 is safe to use. Also, you were told that you are able to sniff subnet traffic, other than that, nothing else is promised nor known. Scan the entire network and access everything you can. Do not let any restrictions, especially with Firefox, stop you if you can change your settings. Don't take no for an answer, the agency needs you! Find and answer the ten questions.
## Submission Format
Enter the answer in the correct box
Example submissions in order of questions:
**(Part 1)**
```
37
```
**(Part 2)**
```
6.3
```
**(Part 3)**
```
Tipton
```
**(Part 4)**
```
directory-name
```
**(Part 5)**
```
1776
```
**(Part 6)**
```
16
```
**(Part 7)**
```
340000
```
**(Part 8)**
```
Johnson
```
**(Part 9)**
```
Sbarro
```
**(Part 10)**
```
192.168.31.6
```
## Questions
1. Your computer has been attached to the corporate switch; however, no DHCP is available. You have arrived to work early and no support is available. All you know is the BRB network's subnet is 172.[16-31].4.0/24. Find the correct subnet, connect to it, and stay connected throughout. The last octet of .91-.95 is safe to use, other than that, nothing is promised nor known. What is the numerical value of the second octet?
2. What is the most common version of OpenSSH on BRB network? (e.g., x.x format, NOT x.xp1)
3. What is the WordPress version 'code name' of the WordPress running on the 'main' BRB site?
4. What directory is entirely disallowed by the WordPress site from web crawlers, except one php file? (e.g., Do not enter any slashes, only directory name and any characters in directory name)
5. Each Blue Ridge Bets account has its own directory and its associated hash within. How many total Blue Ridge Bets account directories are found in the financial server? (e.g., Do not enter any commas. Numbers only!)
6. Intel states that Blue Ridge Bets has bots that appear as players, win money, and keeps it within the company. Intel states that bots can be identified if their hash represents 000 or 0000 or 00000. How many of the total Blue Ridge Bets accounts are bots? (e.g., Numbers only!)
7. Somewhere there is a document that states how much money the bot accounts stole. How much money did the bot accounts win/steal? (e.g., Enter in this format xxxxxx (Numbers only!))
8. What is the last name of William? He is believed to be the author of fraudulent financial earnings documents both public and private.
9. Somebody is trying to send a message to Tom about meeting up tomorrow. Your agency needs this location to catch the perps in the act. Find the messages being sent. What is the store name of the proposed location?
10. What IP address was somebody trying to reach Tom at (Tom?s IP address)?
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Kali#[1-5]  | user     | tartans  |



> Download Resources: [ISO File 7.1MB](https://files-presidentscup.cisa.gov/t05-46c9757257217afd.iso)
# Indicative
## Background
Your network is diverse, with several IoT devices on various subnets. An attacker at a single IP address is targeting your assets. Due to the sensitive nature of the devices on the network, the MAC Addresses have been zeroed out in the packet capture.
## Getting Started
In the CD drive of each of the VMs is a PCAP taken during the attack period. You must identify the IP address which was targeted by a code execution exploit for Trendnet IP Cameras.
You can use any of the provided VMs or download the ISO file to complete the challenge.
## Submission Format
The answer to the challenge is the **IPv4 address** which was targeted with the mentioned exploit.
Example submission:
```
192.168.0.1
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Watercress  | user     | tartans  |
| Karrot      | user     | tartans  |






