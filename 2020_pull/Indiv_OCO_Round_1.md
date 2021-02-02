> Download Resources: [ISO File 58KB](https://files-presidentscup.cisa.gov/1acfbb93-725b-4808-a9b3-ae919d1ce369.iso)
# I thought I checked that
## Background
You are given a vulnerable Linux binary executable file. You must exploit the program and change execution to call the `win` function which prints the flag.
## Getting Started
In the DVD drive of the Kali VM is the Linux binary executable file named `challenge.elf`. You can also download an ISO with the file from this challenge page.
## Submission Format
The token you submit is a 32 character alpha-numeric string.
Example submission:
```
abcdefghijklmnopqrstuvwxyz123456
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Exploiter   | user     | tartans  |




# Is this on the test?
## Background
The company \"Techstory\" was created one year ago and provides online photo storage, as well as a virtual photo book that can be shared with other users. You have been contracted as a penetration tester to evaluate their current environment and attempt to infiltrate their network.
Techstory agreed to provide you with four packet capture files, each showing IP addresses within four different subnet blocks. These blocks are:
* `192.168.58.[40-50]`
* `192.168.132.[70-80]`
* `192.168.176.[110-120]`
* `192.168.210.[160-170]`
Be advised, the packet captures are old and may not accurately portray the current network configuration. You should gather other information about the network and its systems to aid in your analysis. The company will be operating normally with a majority of workers unaware that penetration testing is taking place.
## Getting started 
You have access to a Kali Linux system with no network configuration applied. On its desktop will be a folder named `subnets` which contains the packet captures. You must determine any valid and unused IP addresses to assign to your Kali system. Afterwards, perform reconnaissance and gain access to a vulnerable machine on the network to view the flag.
## Submission Format
When entering your submissions, please enter them in the following format:
1. Correct IP address configuration of Kali machine
2. Host name of vulnerable machine 
3. Port accessed (number, not name) 
4. Flag string found on the vulnerable machine
Example submission:
**Part 1** 
```
4.30.20.100
```
**Part 2**
```
David
```
**Part 3**
```
44
```
**Part 4**
```
Library
```
## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Kali      | user     | tartans  |




# Under Attack
## Background
SSH brute force attacks are a low-effort means for criminals to find accessible systems to use for nefarious purposes. They use dictionaries of common usernames, passwords, and default credentials
and target huge swaths of the Internet looking for susceptible machines. 
Your incident response team has identified suspicious inbound SSH traffic. As an exploitation specialist, the team has asked you to modify the local ssh daemon in order to gain insight into the attacker's password library. This will help protect against similar attacks in the future.
## Getting Started
Log in to your Xubuntu workstation. In the `~/Downloads/` directory, there will be a .tar.gz file containing the ssh server software source code. Your
task is to modify, compile, and install a new daemon that logs, prints, stores, or otherwise saves the passwords
provided by the users attempting to connect to the system.
In a real world scenario, the attacker's password dictionary could consist of thousands of unique passwords. This
exercise is different, and the attacker has a password dictionary with only one entry. Retrieve
the password to complete this challenge.
You will need root access to install your modified ssh daemon. Use `sudo su` to elevate to root privileges.
## Submission Format
The submission for this challenge is an 8-byte value represented by 16 hexadecimal digits. All letters will be lower case.
Example submission:
```
d0d0caca1337beef
```
## System Credentials
| system      | username | password |
|----------------|----------|----------|
| ssh-xubuntu        | prescup     | tartans  |




# Some Assembly Required
## Background
Detecting malware by known signatures is a common practice. However, while signatures can be useful to protect
against more basic threats, they only alert on known matches. In this challenge, you will need to defeat rudimentary signature
detection. There are **10** signatures being detected in this challenge. You must break at least **2** of these.
For the purposes of scoring this challenge, the modified payload must retain at least **3** of its signatures.
## Getting Started
On the desktop, in the **prescup-b5-r1** directory, there are three scripts:
1. generate_raw_binary.sh
2. assemble_payload.sh
3. upload_file.sh
Open a terminal in this directory and run `generate_raw_binary.sh`. It will take 10-15 seconds, and then prompt for a `sudo` password. Enter the password listed below, and the file `asm_code.asm` will be generated.
Next, modify `asm_code.asm` with modified or additional instructions as you see fit, in order to bypass detection.
When you are done, run `assemble_payload.sh` to generate `payload.exe`. This command will also prompt for a `sudo`
password if it has been a while since running the first command.
Finally, run `upload_file.sh`. If you've modified the assembly enough to break up a few signatures, you will receive
a flag. Otherwise, you will be told whether you have not broken enough signatures, or if you've broken too many of them.
## Submission Format
Example submission:
```
0123456789abcdef
```
## Systems and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| sol-kali | user     | tartans  |




# Insider Insidiousness
## Background
  Your pentesting company has been asked by the Security Manager of Questron, Inc. to demonstrate the post-exploitation capabilities of an APT or an insider threat. With this, Questron's IT department and network security team can improve their detection abilities and overall security posture. 
## Getting Started
You have been given access to a Windows 10 host on the Questron network as a domain administrator. You must complete a series of tasks related to files in a shared directory on the machine named FS01.  Standard access to the file share has been disabled, so you should use remote queries to find the answer to each task question (WMI and/or PSRemoting are recommended tactics).
## Questions
1.\tWhich of the top-level directories in the Questron file share is a hidden directory?
2.\tBased on the resources found under the Planning directory, name one of the Questron partner organizations.
3.\tName the Questron project that is not named after a President (excluding the STONEHENGE project)? 
4.\tYou have been asked to identify information within the Project Charter of the STONEHENGE project. View the project documents and give the last name of the Project Lead. 
5.\tLocate an Excel spreadsheet containing a roster of Questron personnel. According to the roster, in what year did COO, Charles Lewis, begin working for Questron?  (_Hint,  this is a hidden file._)

## Submission Format
The answer to the challenge is the token that you will find associated with each task that you are asked to perform.
## Example submissions:
**Question 1:** Directory Name
```
TheDirectory
```
**Question 2:** Partner Names
```
LastName
```
**Question 3:** Organization
```
TheOrg
```
**Question 4:** Project Lead
```
LastName
```
**Question 5:** Year
```
2020
```
  ## System and Tool Credentials
  |  system/tool  | username | password |
  |---------------|----------|----------|
  | win10-desktop | aferguson   | tartans|
  

