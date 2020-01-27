#!/usr/bin/env python3

# smbdig - ver 1.0
# by disastrpc @ github.com/disastrpc
# GNU General Public License Ver 3
# Tool for domain enumeration using RPC and lsat.

# Disclaimer: 
# This tool is intended for legal uses purposes only. The user takes full responsibility
# of any actions taken while using this software. The author accepts no liability for 
# damage caused by this tool. 

VERSION = '1.0.0'

import shlex, subprocess, click, threading, re
from sys import stdout, stderr, argv
from contextlib import redirect_stdout
from impacket.dcerpc.v5 import transport, lsat, lsad, samr
from impacket.dcerpc.v5.nrpc import MSRPC_UUID_NRPC,hDsrGetDcNameEx,hDsrGetDcNameEx2
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection

# Class returns transport objects and binds dce handlers
class TransportHandlerFactory:

    DEFAULT = {
        "user":"",
        "pass":"",
        "domain":"WORKGROUP"
    }

    def __init__(self, host, port, bind_str, verb=False, __trans = None, __dce = None):

        self.__host = host
        self.__port = port
        self.__bind_str = int(bind_str)
        self.__verb = verb
        self.__trans = __trans
        self.__dce = __dce

        self.BIND_STRINGS = {
            1: {'bindstr': fr'ncacn_np:{self.__host}[\pipe\netlogon]'},
            2: {'bindstr': fr'ncacn_np:{self.__host}[\pipe\lsarpc]'},
            3: {'bindstr': fr'ncacn_np:{self.__host}[\pipe\lsarpc]'},
            4: {'bindstr': fr'ncacn_np:{self.__host}[\pipe\samr]'}
        }

    def connect(self):
        try:
            # try to spawn a transport object
            self.__trans = transport.DCERPCTransportFactory(self.BIND_STRINGS[self.__bind_str]['bindstr'])
            # check if credentials can be set
            if hasattr(self.__trans, 'set_credentials'):
                if self.__verb:
                    stdout.write("[*] Set credentials to default values\n")
                self.__trans.set_credentials('', '', 'WORKGROUP', '', '')

            # only use for SAMR bind strings
            if self.__bind_str == 4:
                stdout.write("[*] Using SAMR bind string, setting dport and RemoteHost\n")
                self.__trans.set_dport(self.__port)
                self.__trans.setRemoteHost(self.__host)

                if hasattr(self.__trans, 'preferred_dialect'):
                    self.__trans.preferred_dialect(SMB_DIALECT)

            self.transport_handler = self.__trans
            return self.transport_handler
        except DCERPCException as DCERPCExcept:
            stderr.write(f"[-] {DCERPCExcept}\n")
        except KeyError as kerr:
            stderr.write(f"[-] KeyError: {kerr}\n")
        except Exception as _except:
            stderr.write(f"[-] {_except}\n")
      
    def bind(self, bind):
        # bind handler using LSAT or RPC
        try:
            self.__bind = bind
            if self.__verb:
                stdout.write(f"[*] Binding to {self.__bind}\n")
            self.__dce = self.__trans.get_dce_rpc()
            self.__dce.connect()

            if self.__bind == 'rpc':
                self.__dce.bind(MSRPC_UUID_NRPC)

            elif self.__bind == 'lsat':
                self.__dce.bind(lsat.MSRPC_UUID_LSAT)

            elif self.__bind == 'samr':
                self.__dce.bind(samr.MSRPC_UUID_SAMR)
                handle = samr.hSamrOpenDomain(self.__dce, self.__trans)
                print(handle)
            
            elif self.__bind == 'smb':
                self.__dce.bind()

            stdout.write(f"[+] {self.__bind} handler bind to {self.__host} successful\n")
            return self.__dce
        except DCERPCException as DCERPCExcept:
            stderr.write(f"[-] {DCERPCExcept}\n")
        except KeyError as kerr:
            stderr.write(f"[-] KeyError: {kerr}")
        except Exception as _except:
            stderr.write(f"[-] {_except}\n")



class Librarian:

    ACCESS_MASK_DEF = '0x00000800'
    ACCESS_MASK_GR = '80000000L'

    def __init__(self, handler=None, dce_handler=None, verb=False):
        self.__handler = handler
        self.__dce_handler = dce_handler     
        self.__domain_name = '' 
        self.__verb = verb

    # takes binded instance of a TransportHandler using the samr bind string
    # def samr_dump(self):
    #     print(self.__dce_handler)
    #     resp = samr.hSamrConnect(self.__dce_handler)
    #     print(resp)

    def get_dc_info(self, host):

        args = {
            'lsaquery': fr"rpcclient -W='' -U='' -N -I {host} -c 'lsaquery' 2>&1",
            'smbclient': fr"smbclient -W='' //{host}/ipc$ -U='' -c 'q' 2>&1"
        }

        # get domain name and SID
        out = subprocess.check_output(shlex.split(args['lsaquery'])).decode('utf-8').split('\n')
        self.__domain_name = out[0].split(':')
        self.__domain_sid = out[1].split(':')
        # out = subprocess.check_output(shlex.split(args['smbclient'])).decode('utf-8')
        # print(out)
        stdout.write("[*] Domain information: \n")
        stdout.write(f"[+] Domain name:{self.__domain_name[1]}\n")
        stdout.write(f"[+] Domain SID:{self.__domain_sid[1]}\n")


    def get_dc_name_ext2(self, userlist, verbose):

        if type(userlist) is list:

            stdout.write(f"[*] Found users: \n")
            for user in userlist:
                user = user.strip()
                try:
                   hDsrGetDcNameEx2(self.__dce_handler,NULL,fr'{user}',512,NULL,NULL,NULL,0)              
                except:
                    if verbose:
                        stdout.write(f"[-] '{user}' not found\n")
                    pass
                else:
                    stdout.write(f"[+] '{user}' found on host\n")

    def rid_cycle(self, host):
        pass
    
    def spawn_rid_cycle_daemons(self, host, verb=False, MAX=10000, max_daemons=4):

        DEFAULT_USERS = ["Administrator",
                    "Guest",
                    "krbtgt",
                    "domain",
                    "admins",
                    "root",
                    "bin",
                    "none",
                    "admin",
                    "guest",
                    "administrator"]

        def cycle(host, start, stop): 
            matches = {}
            for i in range(start, stop):
                try:
                    HEX = hex(i)
                    if self.__verb:
                        thread_name = threading.currentThread().getName()
                        stdout.write(f"[*] Cycling {HEX} curr:{i}\\start:{start}\\stop:{stop} | {thread_name}\n")
                    args = fr"rpcclient -W='' -U='' -N -c 'samlookuprids domain {HEX}' {host}"
                    resp = subprocess.check_output(shlex.split(args)).decode('utf-8')       
                    _resp = resp.split(" ")
                    matches[HEX] = _resp[2]
                    stdout.write(f"[+] Name: {_resp[2]} RID: {HEX}\n")
                except:
                    pass
                finally: i+=1
                
            stdout.write("[*] RID matches:\n")
            for key in matches.keys(): 
                stdout.write(f"[*] RID: {key} Name: {matches[key]}")

        daemons = []
        stop_const = int(MAX / max_daemons)
        start = 0
        stop = stop_const

        stdout.write(f"[*] Starting cycling with {MAX} daemon(s)\n")
            
        for i in range(max_daemons):
            daemon = threading.Thread(target=cycle, args=(host,start,stop, ), daemon=True)
            daemons.append(daemon)
            daemon.start()
            stdout.write(f"[*] Started daemon {i}\n")
            start = stop
            stop += stop_const
            
        for i, thread in enumerate(daemons):
            thread.join()

        # try:
        #response = lsad.hLsarOpenPolicy2(self.__dce_handler, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES, '80000000L')
        # except DCERPCException:
        #     stderr.write("[-] ACCESS_DENIED\n")

if __name__ == "__main__":

    HELP_CONTEXT = ['-h','--help']

    def show_banner():
        stdout.write(fr'''
   ___ _ __ ___ | |__   ___ __ _| |_ 
  / __| '_ ` _ \| '_ \ / __/ _` | __|
  \__ \ | | | | | |_) | (__ (_| | |_ 
  |___/_| |_| |_|_.__/ \___\__,_|\__|   
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~           
  | GNU Public | by disastrpc | {VERSION} |'''+'\n')

    def show_help():
        show_banner()
        stdout.write(r'''
SMB enumeration tool built around the impacket package.
    Usage:
        smbcat <options> <host:port>

Options:
    -m  --mode  <string>        =>  Specify the mode the program will use. Modes are:
                                    'dict'  => Dictionary attack. Must provie username list.
                                    'cycle' => Cycle user RIDs. You can specifiy a max count
                                               to cycle on. Default is 10,000.
    -U  --users <path>          =>  Specify user list
    -u  --user  <string>        =>  Specify a user
    --max-rid-count <int>       =>  Specify max RID count to cycle until. For use with 'cycle' mode.
    -v  --verbose               =>  Be more verbose

Examples:
    smbcat -m dict -v -U /root/users.txt 10.1.5.10:135
        '''+'\n')

    if argv[1] in HELP_CONTEXT:
        show_help()
    else:
        @click.command()
        @click.option('-m','--mode', type=click.Choice(['dict', 'cycle'], case_sensitive=False))
        @click.option('-U','--user-list', 'userlist')
        @click.option('-u','--user')
        @click.option('-v','--verbose', 'verb', count=True)
        @click.option('--hash-dump', 'hashdump', count=True)
        @click.argument('target_host')
        def main(mode='', userlist='', user='', verb=False, hashdump=False, target_host=''):

            show_banner()

            ths = target_host.split(':')
            host, port = ths[0], int(ths[1])
            # print(host, port, verb, users)
            if mode == 'dict':
                try:
                    with open(userlist, 'r') as usersf:
                        userlist = usersf.readlines()
            # print(host, port, verb, users)
                        handler = TransportHandlerFactory(host, port, verb=verb, bind_str=1)
                        handler.connect()
                        dce_handler = handler.bind(bind='rpc')

                        if verb:
                            verbose=True 
                        else:
                            verbose=False   

                        rpc_librarian = Librarian(handler, dce_handler)

                        rpc_librarian.get_dc_info(host)
                        rpc_librarian.get_dc_name_ext2(userlist, verbose)

                        # samr_handler = TransportHandlerFactory(host, port, verb=verb, bind_str=4)
                        # samr_handler.connect()
                        # samr_dce_handler = samr_handler.bind(bind='samr')

                        # samr_librarian = Librarian(samr_handler, samr_dce_handler)
                        # samr_librarian.samr_dump()
                except FileNotFoundError as ferr:
                    stderr.write(f"[-] {ferr}\n")
            elif mode == 'cycle':
                # handler = TransportHandlerFactory(host, port, bind_str=4, verb=verb)
                # handler.connect()
                # dce_handler = handler.bind(bind='samr')
                librarian = Librarian(verb=True)
                librarian.spawn_rid_cycle_daemons(host)
            else:
                stderr.write("No user list found\n")
        main()


        


