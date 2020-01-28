# smbcat
smbcat (or smbcataloguer) is a Domain Services enumeration tool inspired by [enum4linux](https://github.com/portcullislabs/enum4linux) and built around the [impacket](https://github.com/SecureAuthCorp/impacket/) package. While still in development, it is capable of enumerating domain information by wrapping around tools like rpcclient and smbclient, or directly calling remote discovery functions through DCE/RPC (LSAD, LSAT, and SAMR will be added in future releases).

Future features:
  - SID cycling
  - NT and NTLM password dumps
  - LSAD SID cycling
```  
Usage:
     smbcat <options> <host:port>

Options:
    -m  --mode  <string>        =>  Specify the mode the program will use. Modes are:
                                    'dict'  => Dictionary attack. Must provide username list.
                                    'cycle' => Cycle user RIDs. You can specifiy a max count
                                               to cycle on. Default is 10,000.
    -U  --users <path>          =>  Specify user list
    -u  --user  <string>        =>  Specify a user
    --max-rid-count <int>       =>  Specify max RID count to cycle until. For use with 'cycle' mode.
    -v  --verbose               =>  Be more verbose

Examples:
    smbcat -m dict -v -U /root/users.txt 10.1.5.10:135
```
