    =============================================================
    
    __________                         _________               
    \______   \_______   ____   ______ \_   ___ \ __ ________  
     |     ___/\_  __ \_/ __ \ /  ___/ /    \  \/|  |  \____ \ 
     |    |     |  | \/\  ___/ \___ \  \     \___|  |  /  |_> >
     |____|     |__|    \___  >____  >  \______  /____/|   __/ 
                            \/     \/          \/      |__|    
    
    =============================================================

# Approaching a challenge
* Notes
    * Read the challenge title and extract clues
    * Read the challenge description and extract clues
    * Read every sentence and extract clues
    * Compile every clue and piece of information you've been given along the way and step back after 1 hour
* Landing on a linux box
    * history
    * find / -mtime -30 2>/dev/null
    * grep -iR pcup{ .
    * updatedb/locate (special file extensions relevant to challenge, ex. png)
    * cat other users .bash_history files

# OCO

## Web Hacking

* Check the source
* Check for sql injection (every field)
* Check for command injection (every field - ``, $(), ;, || id ||, && etc)
* Use Perl one-liner reverse shells (they use docker images w/perl by default)
    * https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl
* Run everything through Burp

## Windows

* Use `more` to open Alternate Data Streams
* Base64: [System.Text.Encoding]::UTF8.GetSTring([System.convert]::FromBase64String("lkjasflkjasdfklj"))
* Mimikatz syntax
* Responder syntax
* Meterpreter Post
    * Dumphashes
    * lsa_dump_sam
    * dc_sync
    * steal_token

## Linux
* Password bruteforce wordlist mangling generation:
    * rsmangler -p -d -r -t -T -c -u -l -s -e -I --punctuation -a -C --pna --pnb --na -nb --force --space --file words.txt --output wordsmangled.txt

# DCO

## Snort
* Basic rule syntax:
    * alert ip 37.46.12.6 !502 -> any any (msg: "Non-Authorized port from PLC"; sid:2233002; rev:1;)

## PCAPS

### Wireshark
* Filter and export selected packets often to speed up analysis
* dns.qry.name contains "ala.net"
* Look for python-requests as user agent <- devs are lazy

### Misc
* Convert pcapng to pcap
    * editcap -F pcap test.pcapng test.pcap 
* Merge convert
    * mergecap -F pcap -w outfile.pcap infile_1.pcapng infile_2.pcapng
* Distill to netflow
    * nfpcapd -r infile.pcap -S 1 -l output_directory/
* Distill to bro
    * zeek -r pcap_to_log.pcap local "Log::default_rotation_interval = 1 day"
* Detect beacons/malicious traffic
    * https://github.com/activecm/rita

### SecurityOnion
* Make sure to convert from pcapng to pcap first vv
    * so-import-pcap /mnt/hgfs/VMShare/my_pcap.pcap
* so-reset
* https://user-images.githubusercontent.com/7849311/57718306-029d5180-764b-11e9-86b9-cf0f69c56ac6.jpg
* Zeek file extraction:
    * /nsm/zeek/extracted/complete
* DNS anomaly detection (exfil)
    * https://docs.securityonion.net/en/2.3/dns-anomaly-detection.html
* ICMP anomaly detection (c2)
    * https://docs.securityonion.net/en/2.3/icmp-anomaly-detection.html
* If trying to find a specific attack (and not a vuln scanner) - look at user agents (python-requests)
    * Security Onion - HTTP dashboard, then scroll through user agents


## Memory Forensics

### SIFT 
* rekal -f image.vmem
    * > pslist
    * > procinfo <pid>
    * > desktop
    * > sessions
    * > threads
    * > connections
    * > devicetree
    * > dt("_EPROCESS")
    * > dlllist <pid>
    * > handles <pid>
    * > filescan output="filescan.txt"
    * > hives
    * > regdump
    * > vmscan
    * > certscan
    * > mimikatz
    * > netscan
    * > netstat
    * > dns_cache
    * > messagehooks
    * > ... more -- see their cheatsheet for dumping, rootkits, etc

* rekal for malicious procs
    * > describe(pstree) - View columns to output
    * > select \_EPROCESS,ppid,cmd,path from pstree()
    * > malfind <pid> 
    * > ldrmodules <pid> verbosity=3   (detect unlinked dlls)

* vol.py command –f /path/to/windows_xp_memory.img --profile=WinXPSP3x86
    * > imageinfo (help identify profile)
    * > pslist
    * > connscan
    * > files
    * > imagecopy
    * > procdump
    * > sockscan
    * > ... more -- see cheatsheet for everything else...
	
## HDD Forensics
* Assume all users are using the same box as your analysis box. If you want some info - replace your entire Program Files\whatever_program directory with theirs
* log2timeline –r –p –z <system-timezone> –f <type-input> /mnt/windows_mount –w timeline.csv

### Windows
* Procmon:
    * Filter - Process Name is blah.exe then Include
    * Filter - Use Path contains c:\Users\student\desktop\Challenge\ then include
* Always check for Shadow Volumes with Shadow Explorer 
* Break veracrypt partitions: truecrack -t scada101.mp4 -c abcdefghijklmnopqrstuvwxyz -s 4 -m 4 -v -h
* Extracting files to show metadata
    * mmls analysis.dd (shows partitions)
    * mmcat analysis.dd 2 > /home/examiner/Desktop/cases/ntfs.dd
    * Show MFT entries: fls -f ntfs -r ntfs.dd
    * Extract the mft: icat -f ntfs ntfs.dd 0 > mft.dd
* Extracting data from slack space
    * mmls analysis.dd
    * fsstat -o 63 analysis.dd   (where 63 is the start of a block)
    * mount -o ro.noatime,loop,offset=$((63\*512)) analysis.dd /mnt/windows_mount
    * /opt/lsoft/DiskEditor/DiskEditor.sh   <- good tool
* Look at shadow volumes
* Look at firefox/IE/Chrome cache
* Hashes, domain admin creds, domain creds (dcsync)
* Cached registry creds (IMAP Outlook)
    * $data = Get-ItemProperty "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\Charles jackson\987124987102847\0000000009"
    * $pdata = $data[1..$data.Length]
    * [System.Text.Encoding]::Unicode.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($pdata, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))

# Escape Room Thoughts
* Closely record all hints
    * What items do you have? Where did you get them? 
    * Which hints came from where?
    * What is the mentality of the individual in the environment?
* What happens when boxes come online?
    * DHCP leases are requested, in order of which devices boot first.
* Expect there to be Red Teaming
    * Be able to do a dump hashes, impersonate token, lateral move to DC, dump hashes, repeat

