> Download Resources: [ISO File 900KB](https://files-presidentscup.cisa.gov/b11-2klzm99bamhqm3hy.iso)
# More Than Meets the Eye - Revenge of the Code
## Background
You have been given four programming related problems to solve. Each problem will provide you with one or more tokens for submission towards the overall completion of this challenge. Problems will require you to analyze code as well as ask you to write your own code to efficiently complete the required tasks.
  ## Getting Started
You have the option to use either a Kali or Windows 10 workstation for this challenge. Problem set data can be found attached to the CD drive of either system in a  folder called \"Challenge Data\". Further instructions will be included with each problem set within the Challenge Data folder. Rust and Cargo functions on Kali can be run from /root/.cargo/bin/ with the sudo command, e.g. `sudo /root/.cargo/bin/rustc myrustfile.rs`, should they fail to run as the standard user.
Two of the problems will require that you submit your code to a grading server. The grading server will verify that the code runs as required. The grading server will then return your token(s) or the evaluation results if your code fails to meet the minimum requirement. The results will also append the code that was used so that you can verify your file was uploaded properly.
Notes on grading:
1. The grading checks will run once per minute, but will only verify your code IF a new code file was submitted in the last minute. Until you submit your first file, the results files will be empty and will only be populated for the problems that you submit.
2. The grading checks will stop running for a respective problem once it has been passed in full.
3. Using WinSCP from Optimus is an easy way to check the results files for updates since the timestamps will change when an update is made. Simply refresh the files to see your latest results (remember that it may take a minute to run the next iteration of grading). You latest code will be appended to the results/token files in order for you to verify what was graded.
4. The last file(s) graded will also be tagged with \"-checked\". If you upload new files, this \"-checked\" file will be overwritten with your latest upload at the next grading iteration.
  ## Winning Conditions
In order to receive full credit for this challenge all four problems must be solved as expected and one problem has two levels of completion, making for five tokens overall. A grading server will be used to evaluate and generate the tokens on your behalf for that specific challenge.
## Submission Format
Each token found within this challenge consists of a 12-character string made up of lowercase letters and numbers. The lowercase l and the number 1 have been removed to eliminate any confusion between the two. In the case of problem #4, which has two tokens to retrieve, you will be told which is which for submission.
All 5 parts will follow the same token format for submission. 
Example submission:
**Part 1 of 5:**
```
a2b3z5y6d8g9
```
**Part 2 of 5:**
```
caigyxf27e2v
```
**Part 3 of 5:**
```
re5o9k8ab304
```
**Part 4 of 5:**
```
9ad2a0p64o2h
```
**Part 5 of 5:**
```
0ypzf5wxiq4y
```
## Hints
Even though you are looking at code, the solution to a problem does not always require writing new code.
  ## System and Tool Credentials
  | system/tool                | username | password |
  |---------------------------|--------------|-----------|
  | Optimus (Windows 10)              | user     | tartans  |
  | Megatron (Kali)                             | user     | tartans  |






# Who Let Him Be An Admin?
## Background
We are conducting a vulnerability assessment of our internal systems. We recently discovered that our former network administrator was not entirely truthful on his resume. We want to make sure that this did not impact the security of these systems and need you to check the state of these systems to ensure they are secure.
## Getting Started
You are given a Kali VM within the same network as two other systems. You should begin by running appropriate scans against these targets.
The two systems have the following IP addresses:
- 10.10.10.60
- 10.10.10.61
There are four tokens to be found for the challenge:
- One is in a database
- Three are from a web server
## Submission Format
Example submission:
**Part 1 of 4:**
```
0123456789abcdef
```
**Part 2 of 4:**
```
oozuvohxaoc4phoo
```
**Part 3 of 4:**
```
res3keibohhieph9
```
**Part 4 of 4:**
```
shien4quexaeheiz
```
Make sure that you supply each flag in the correct box.

## Systems and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| client | user     | tartans  |





# Dirty Work
## Background
With the right intel, an SSH brute force attack can provide access to remote computer systems for offensive cyber operators. In this challenge, intelligence analysts have identified the likely values of a specific threat's host, username, and password composition. Your mission is to process the data, conduct a brute-force attack to determine the correct credentials, and then log in and retrieve a submission string.
The intelligence report indicates that the known target's username is `kowalski` and his system has IP address `192.168.1.100`. His password is a compound string comprised of three words concatenated together, in the form `LoremIpsumDolor`. Each word is taken from a dictionary with a distinct theme, and each theme is represented only once. For example, if the themes were \"Trees,\" \"Trucks\ and \"Furniture,\" the password might be \"SuburbanCouchWalnut\".
The three exact words that make up the password are unknown, but a dictionary was generated with strong candidates. Unfortunately, a junior analyst overwrote the master list while attempting to generate permutations for a brute force attack. At that time, intelligence believed that numbers and special characters may have been included in the password. That is no longer believed to be the case.
What remains of the dictionary are three files with modified entries. Each line represents one potential password, and each potential password may be unaltered, altered with numbers, or altered with symbols and/or spaces. Most words appear, altered or unaltered, many times. Further, it is known that the junior analyst had identified a handful of words that are highly likely to comprise the final password. These favorite words are known to appear only once in each of the three dictionary files.
The following number/letter substitutions should be corrected:
|number|letter|
|---|---|
|0|O|
| 1  |  L  |
| 2   |  Z  |
| 3  | E  |
| 4  |  A  |
| 5   |  S  |
| 7  |  T  |
| 8  |  B  |
| 9  |  G  |
All special characters should be removed from each password candidate, including spaces.
## Getting Started
Log in to your Kali workstation. In the `~/wordlist/` directory, there will be three text files containing the mutated list of words generated by the junior analyst. Clean up the files, identify the words that occur only once in each file, then determine the target's password. Log in to the target machine using the credentials you discover and find the submission token in submission.txt in the user's home directory.
## Submission Format
The submission for this challenge is an 8-byte value represented by 16 hexadecimal digits. All letters will be lower case.
Example submission:
```
d0d0caca1337beef
```
## System Credentials
| system      | username | password |
|----------------|----------|----------|
| kali       | user     | tartans  |



> Download Resources: [PDF File](https://files-presidentscup.cisa.gov/b09-IncidentReport-v3.pdf)
# Remote Correlation
## Background
You are provided an incident report from Company XYZ. The report describes the tactics of the adversary who attacked the company's Windows infrastructure. Details about the attack should be used to attribute artifacts on the provided Windows computers to the same attacker that compromised Company XYZ.   
## Getting Started
Read the Company XYZ incident report in the attached PDF.  
After gathering details from the report, you must use your provided Windows workstation to audit 3 remote Windows workstations.   
The 3 remote workstations will have various firewall, scheduled task, registry, and/or WMI artifacts configured. Some of the artifacts on the remote workstations will be benign. Other artifacts on the remote workstations will have similar characteristics to those seen in the incident report.   
Your task is to list the hostnames which have artifacts with similar characteristics to those gathered from the provided incident report.
## Submission Format
The tokens you submit will be the hostnames which have artifacts with similar characteristics to those gathered from the incident report.   
There are 4 parts to a submission. The 4 parts are derived from the types of artifacts that exist on the remote machines: Firewall, Scheduled Task, Registry, and WMI.  Each part can have one or more hostnames to list as part of the submission. For parts that have more than 1 hostname, enter the hostnames in alphabetical order, separated by a space.
Example submissions:
**Part 1 of 4:**
```
HostABC
```
**Part 2 of 4:**
```
HostABC HostDEF
```
**Part 3 of 4:**
```
HostABC HostDEF HostXYZ
```
**Part 4 of 4:**
```
HostXYZ
```

## System and Tool Credentials
| system/tool | username | password | remote
|-------------|----------|----------|-----------|
| moe | user     | tartans  |  no
| eeny | user     | tartans  |  yes 
| meany | user     | tartans  |  yes 
| miney | user     | tartans  |  yes 





> Download Resources: [ISO File 4.0MB](https://files-presidentscup.cisa.gov/b10-k9mlh3v0jr.iso)
# OpenSSL && Open Sesame
## Background
You are conducting a penetration test. Your team has accessed encrypted files. If you are able to crack this data at rest, the penetration test is a success as you've shown the data the client prioritizes was lost and compromised.
## Getting Started
There are five directories on the attached iso. Answer the questions below as you decrypt the files. 

## Questions
Stage 0:  Decrypt email5.txt.enc with passphrase `tartans`. **Provide only the username of email address** (the part before the `@` sign)
Stage 1:  Decrypt id13.txt.enc with the key and IV also located in the directory. **Provide the decrypted output**
Stage 2: Decrypt PIN23.txt.enc. Potential Keys and IVs are located in the directory. **Provide the decrypted output**
Stage 3: Decrypt phone235.txt.enc. Keys, IVs, and Salts that may have been utilized are located in the directory. **Only submit numbers, no dashes or other special characters.* 
Stage4:  Decrypt fingerprint_b64_467.txt.enc. There is an encryption.log that details enough specifics on how the various data was encrypted. **Provide the decrypted data as a base64 encoded string** 
## Submission Format
Example submissions in order of questions:
Part 1 of 5:
```
rnewman
```
Part 2 of 5:
```
31752
```
Part 3 of 5:
```
23090013918
```
Part 4 of 5:
```
1185557983
```
Part 5 of 5:
```
NTQ2NDI4MDc=
```
## System and Tool Credentials
| system/tool    | username | password |
|----------------|----------|----------|
| OS&&OS-Kali           | user     | tartans  |


> Let's Go Phishing
## Background
You have been tasked to conduct a penetration test of the `challenge.pc` domain and associated systems.  The end-goal of this test is to gain access to a standalone machine with the name `Dev` (this machine is not joined to the challenge.pc domain but is part of the company enterprise). 
The `Dev` machine is owned and operated by a user who always forgets their local administrator password. The IT department has made it such that they are able to RDP from the Domain Controller to the user's machine, but this user does not like to wait for the IT department to help her. The user has installed her own backdoor to the system which allows her to reset a forgotten password at any time by taking advantage of the sticky keys hot key. 
## Getting Started
You are given Kali VMs to utilize for the assessment.
There is an FTP server on the network at `ftp.challenge.pc`. To simulate a user running a malicious program on their workstation, the FTP site is being polled — any file with a `.exe` extension will be downloaded and run on a domain joined user VM. Any uploaded file will only run for 5 seconds before being terminated. If you wish to upload a file more than once, change the name of the file that is being uploaded.
Use a Kali VM to create a `.exe` which gives you access to the user VM. The user machine will have a token in `C:\\token\\usertoken.txt`. You should then escalate privileges and pivot to the domain controller to view the token in `C:\\token\\dctoken.txt` on the domain controller.  The final token is located at `C:\\token\\devtoken.txt` on the Dev machine. 
## Submission Format
All submission tokens will be 16 character alphanumeric strings (all lowercase). 
The user token will be located at `C:\\token\\usertoken.txt` on the user machine.  
The domain controller token will be located at `C:\\token\\dctoken.txt` on the domain controller.   
The dev token will be located at `C:\\token\\devtoken.txt` on the Dev machine. 
Example submission:
**(Part 1 of 3)** User Token  
```
abcd1234efgh5678
```  
**(Part 2 of 3)** Domain Controller Token
```
dcba4321hgfe8765
```
**(Part 3 of 3)** Dev Token
```
wxyz0987stuv2468
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Phisherman| user     | tartans  |


