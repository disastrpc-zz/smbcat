#!/usr/bin/env python3

# smbcat - ver 1.1.2
# by disastrpc @ github.com/disastrpc
# GNU General Public License Ver 3
# Tool for domain enumeration using RPC and lsat.

# Disclaimer:
# This tool is intended for legal uses purposes only. The user takes full responsibility
# of any actions taken while using this software. The author accepts no liability for
# damage caused by this tool.

VERSION = '0.1.0'

try:
    from Queue import Queue
except ImportError:
    from queue import Queue

import shlex, subprocess, click, threading, re
from pathlib import Path
from sys import stdout, stderr, argv
from contextlib import redirect_stdout
from impacket.dcerpc.v5.samr import NULL
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
                self.__trans.set_credentials('', '', 'WORKGROUP', '', '', '')

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
                stdout.write(f"[*] Binding to {self.__bind.upper()}\n")
            self.__dce = self.__trans.get_dce_rpc()
            self.__dce.connect()

            if self.__bind == 'rpc':
                self.__dce.bind(MSRPC_UUID_NRPC)

            elif self.__bind == 'lsat':
                self.__dce.bind(lsat.MSRPC_UUID_LSAT)

            elif self.__bind == 'samr':
                self.__dce.bind(samr.MSRPC_UUID_SAMR)
                handle = samr.hSamrOpenDomain(self.__dce, self.__trans)

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

class LibrarianTaskDaemonizer:

        def __init__(self, name, func, max_subproc, args=[], kwargs={}, daemonize=True):
            self.__name = name
            self.__func = func
            self.__args = args
            self.__kwargs = kwargs
            self.__queue = Queue()
            self.__results = []
            self.__max_subproc = max_subproc
            self.__daemonize = daemonize
            self.__daemons = []
            self.__daemon = None

            if self.__daemonize:
                TM = 'daemon'
            if not self.__daemonize:
                TM = 'thread'

        def spawn_bulk(self):

            if self.__args and self.__kwargs:
                stderr.write("[-] Error: Cannot provide args and kwargs together")

            # spawn daemons
            for i in range(self.__max_subproc):
                self.__daemon = threading.Thread(name=self.__name,
                                            target=self.__queue.put(self.__func),
                                            args=(self.__args,),
                                            daemon=self.__daemonize)

                self.__daemons.append(self.__daemon)
                self.__daemon.start()
                stdout.write(f"[*] Started daemon in batch: {self.__name}\n")

            return self.__daemons

        def spawn(self):

            self.__daemon = threading.Thread(name=self.__name,
                                            target=self.__func,
                                            args=self.__args,
                                            daemon=self.__daemon)

            stdout.write(f"[*] Started daemon {self.__name}\n")
            return self.__daemon.start()


        def join(self, daemons=None):
            if not daemons is None:
                 self.__daemons = daemons

            for i, thread in enumerate(self.__daemons):
                thread.join()

        def get(self):
            while not self.__queue.empty():
                result = self.__queue.get()
                self.__results.append(result)
            return self.__results


class Librarian:

    ACCESS_MASK_DEF = '0x00000800'
    ACCESS_MASK_GR = '80000000L'

    def __init__(self, handler=None, dce_handler=None, verb=False):
        self.__handler = handler
        self.__dce_handler = dce_handler
        self.__domain_name = ''
        self.__verb = verb
        self.__daemonizer = None

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
        try:
            stdout.write(f"[*] Attempting LSA query on {host}\n")
            # get domain name and SID
            out = subprocess.check_output(shlex.split(args['lsaquery'])).decode('utf-8').split('\n')
            self.__domain_name = out[0].split(':')
            self.__domain_sid = out[1].split(':')
            # out = subprocess.check_output(shlex.split(args['smbclient'])).decode('utf-8')
            # print(out)
            stdout.write("[*] Domain information: \n")
            stdout.write(f"[+] Domain name:{self.__domain_name[1]}\n")
            stdout.write(f"[+] Domain SID:{self.__domain_sid[1]}\n")
        except:
            stdout.write("[-] Unable to perfom lsaquery\n")

    def get_dc_name_ext2(self, userlist, verbose):

        if type(userlist) is list:

            user_matches=[]
            for user in userlist:
                user = str(user.rstrip())
                try:
                    hDsrGetDcNameEx2(self.__dce_handler,NULL,f'{user}\x00', 512, NULL, NULL,NULL, 0)
                except:
                    if verbose:
                        stdout.write(f"[-] '{user}' not found\n")
                    pass
                else:
                    user_matches.append(user)
                    stdout.write(f"[+] '{user}' found on host\n")

            if len(user_matches) != 0:
                stdout.write("[+] Matches:\n")
                for m in user_matches:
                    stdout.write(m+'\n')
            else:
                stdout.write("[-] No matches found\n")


    def rid_cycle_slr(self, host, MIN=0, MAX=10000, verb=False, daemonize=True):

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

        matches = {}
        for i in range(MIN, (MAX + 1)):
            try:
                HEX = hex(i)
                if self.__verb:
                    thread_name = threading.currentThread().getName()
                    stdout.write(f"[*] Cycling {HEX} curr:{i}\\start:{MIN}\\stop:{MAX} | {thread_name}\n")

                args = fr"rpcclient -W='' -U='' -N -c 'samlookuprids domain {HEX}' {host}"
                resp = subprocess.check_output(shlex.split(args)).decode('utf-8')
                _resp = resp.split(" ")
                matches[HEX] = _resp[2]
                match = f"[+] Name: {_resp[2]} RID: {HEX}\n"
                stdout.write(match)
            except:
                pass
            finally:
                i+=1

        return matches

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
        '''+'\n')

    if argv[1] in HELP_CONTEXT:
        show_help()
    else:
        @click.command()
        @click.option('-m','--mode', type=click.Choice(['dict', 'cycle'], case_sensitive=False))
        @click.option('-U','--user-list', 'userlist')
        @click.option('-u','--user')
        @click.option('-v','--verbose', 'verb', count=True)
        @click.option('-o','--output')
        @click.option('--daemon-count', 'daemons', type=click.INT, default=4)
        @click.option('--rid-cycle-start', 'rid_start', type=click.INT, default=0)
        @click.option('--rid-cycle-stop', 'rid_stop', type=click.INT, default=10000)
        @click.option('--hash-dump', 'hashdump', count=True)
        @click.argument('target')
        def main(mode='',
                userlist='',
                user='',
                verb=False,
                output='',
                daemons=1,
                rid_start=0,
                rid_stop=10000,
                hashdump=False,
                target=''):

            show_banner()
            try:
                ths = target.split(':')
                host, port = ths[0], int(ths[1])
            except IndexError:
                host, port = target, 135
            if mode == 'dict':
                try:
                    with open(userlist, 'r') as usersf:
                        
                        if port is None:
                            print('here')
                        userlist = usersf.readlines()
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

                stdout.write("[*] Starting RID cycling\n")
                stdout.write(f"[*] Daemon count: {daemons}\n")
                stdout.write(f"[*] RID cycle start: {rid_start}\n")
                stdout.write(f"[*] RID cycle stop: {rid_stop}\n")

                # check if rpcclient is available
                if not check_tool('rpcclient'):
                    stderr.write("[-] rpcclient not found in PATH\n")
                    exit()

                # handler = TransportHandlerFactory(host, port, bind_str=4, verb=verb)
                # handler.connect()
                # dce_handler = handler.bind(bind='samr')
                librarian = Librarian(verb=verb)
                stop_const = int(rid_stop / daemons)
                spawned_daemons = []
                rid_stop = rid_start + stop_const

                for i in range(0, daemons):

                    thread_name = host + f'-daemon{i}'

                    daemonizer = LibrarianTaskDaemonizer(name=thread_name,
                                            func=librarian.rid_cycle_slr,
                                            max_subproc=daemons,
                                            args=[host,rid_start,rid_stop,verb])

                    daemonizer.spawn()
                    rid_start = rid_stop + 1
                    rid_stop += stop_const
                    spawned_daemons.append(daemonizer)

                results = []
                for i, daemon in enumerate(spawned_daemons):
                    daemon.join()

                results = daemonizer.get()
                print(results)

            else:
                stderr.write("No user list found\n")

                    # check if a tool is present on system
        def check_tool(tool):

            from shutil import which
            return which(tool) is not None

        main()
