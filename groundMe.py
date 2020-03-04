#!/usr/bin/env python3
import argparse
import subprocess
import sys
import re
import os
import base64
from datetime import datetime

pullPCAPS = """mkdir /tmp/{folder};
for i in `find /nsm/sensor_data/ -name *.log.* -type f`;
do tcpdump -nr $i -w /tmp/{folder}/`echo $i | awk -F/ '{{print $NF}}'`.pcap {filters};
done;
mergecap -w /tmp/{folder}/all.pcap /tmp/{folder}/*;
echo '***>';
base64 /tmp/{folder}/all.pcap;
echo '<***';
rm -rf /tmp/{folder}
""".replace('\n', '')

class remoteHost():
    def __init__(self, hostname):
        self.hostname = hostname
        self.user = ""

    def execute(self, command):
        if self.hostname == "localhost":
            cmd = ["bash", "-c", command]
        else:
            self._userCreds()
            cmd = ["ssh", "{}@{}".format(self.user,self.hostname), command]

        ssh = subprocess.run(cmd, stdout=subprocess.PIPE)
        self.output = ssh.stdout.decode("utf-8")

    def getFile(self, dest):
        time = datetime.now().strftime("%H%M%S")
        try:
            # FIX THIS HERE
            encodedFileStr = self.output.replace("***>","").replace("<***","")
            # END FIXING 
            encodedFileBytes = base64.b64decode(encodedFileStr)
            finalDest = dest + "/" + self.hostname + "_" + time + ".pcap"
            with open(finalDest,'bw') as f:
                f.write(encodedFileBytes)
        except AttributeError as E:
            print(E)
            print("No file returned")

    def _userCreds(self):
        if not self.user:
            if "@" in self.hostname:
                self.user, self.hostname = self.hostname.split("@")
            else:
                self.user = input("Enter user for {}:".format(self.hostname))
            
    def __repr__(self):
        return "[Hostname:{},Username:{}]".format(self.hostname, self.user)
    
    def __str__(self):
        return self.__repr__()


def buildPCAPCMD(destFolder, inFilters):
    global pullPCAPS
    if inFilters:
        filterstring = inFilters[0]
        try:
            for filt in inFilters[1:]:
                filterstring = filterstring + " and " + filt
        except IndexError:
            print("Filter index Error")
            pass
    else:
        filterstring = ""
    pullPCAPS = pullPCAPS.format(folder=destFolder, filters=filterstring)

 
def main():
    global pullPCAPS
    defaultDir = "{}_PCAPS".format(datetime.now().strftime("%Y%m%d-%H%M%S"))
 
    parser = argparse.ArgumentParser(description="Connect to remote sensor to pull logs.",
                                     epilog="Output files will be hostname_timestamp.pcap\n")
    parser.add_argument('host',
                        nargs='+',
                        help='Host to connect to. Use "localhost" to run locally')
    parser.add_argument('-f', '--filter',
                        action="append",
                        help="TCPDUMP filter string. Multiple filters will be AND'ed together. e.g. -f \"host 192.168.0.1\" -f \"dst port 22\" will become \"tcpdump host 192.168.0.1 and dst port 22\"\n To use complex search strings wrap them in quotes. e.g. -f \"host 192.168.0.1 or host 192.168.0.2\" -f \"not icmp\" will become \"tcpdump host 192.168.0.1 or host 192.168.0.2 and not icmp\"")
    parser.add_argument('-o', '--output',
                        default=defaultDir,
                        help='Output folder to store the resulting PCAPS. Default is ./<dtg>')
    args = parser.parse_args()

    hosts = [remoteHost(host) for host in args.host]

    # Handle already existing folder
    try:
        os.mkdir(args.output)
    except FileExistsError:
        pass

    if args.filter:
        buildPCAPCMD(defaultDir, args.filter)
    else:
        buildPCAPCMD(defaultDir, "")
    [host.execute(pullPCAPS) for host in hosts]
    [host.getFile(args.output) for host in hosts]

if __name__ == "__main__":
    main()
