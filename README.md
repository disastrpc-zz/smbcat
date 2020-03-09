# smbcat
smbcat (or smbcataloguer) is a Domain Services enumeration tool inspired by [enum4linux](https://github.com/portcullislabs/enum4linux) and built around the [impacket](https://github.com/SecureAuthCorp/impacket/) package. While still in development, it is capable of enumerating domain information by wrapping around tools like rpcclient and smbclient, or directly calling remote discovery functions through DCE/RPC (LSAD, LSAT, and SAMR will be added in future releases).

Future features:
  - SID cycling
  - NT and NTLM hash dumps
  - LSAD SID cycling
```  
    Usage:
        smbcat <options> <host:port> [Default: 135]
Options:
    -m  --mode  <string>        =>  Specify the mode the program will use. Modes are:
                                    'dict'  => Dictionary attack. Must provie username list.
                                    'cycle' => Cycle domain RIDs. You can specifiy a max count
                                               to cycle on. Default is 10,000.
    -U  --user-list <path>      =>  Specify user list
    -u  --user  <string>        =>  Specify a user
    -o  --output <path>         =>  Output to file
    --daemon-count  <int>       =>  Number of daemons to spawn for the specified operation
    --rid-cycle-start <int>     =>  Start of RID cycle, if not specified default is 0.
    --rid-cycle-stop <int>      =>  Specify max RID count to cycle until. Default is 10,000.
    -v  --verbose               =>  Be more verbose
Examples:
    smbcat -m dict -v -U /root/users.txt 10.1.5.10:135
    smbcat -m cycle --rid-cycle-start=5000 --rid-cycle-stop=30000 --daemon-count=5 10.12.154.10:139
```
