#! /usr/bin/env python3
import argparse
import sys
from scapy.all import *
import signal

# This class tracks a flow, storing the 
# following paremeters
#   - Last pkt timestamp (last seen)
#   - Pkt count
#   - Sum of interarrival times

def signal_handler(signal, frame):
    print(" %d packets processed" % cnt)

signal.signal(signal.SIGINT, signal_handler)
cnt = 0

def main(argv):
    global cnt
    parser = argparse.ArgumentParser(prog=argv[0],description='Calculates interarrival time for all flows in a pcap file')

    parser.add_argument('-i', '--input', metavar='<input trace file>', 
        help='Path to input trace file', required=True)

    parser.add_argument('-o', '--output', metavar='<output trace file>', 
        help='Output file name', required=True)

    parser.add_argument('-s', '--srcmac', metavar='<source MAC>', 
        help='Source MAC address to use on packets', required=True)

    parser.add_argument('-d', '--dstmac', metavar='<destination MAC>', 
        help='Destination MAC address to use on packets', required=True)

    args = vars(parser.parse_args())

    dstmac = args['dstmac']
    srcmac = args['srcmac'] 
    in_file = args['input']
    out_file = args['output']

    cnt = 0
    for pkt in PcapReader(in_file):
        try:
            # pkt.show()
            pkt = Ether(src=srcmac,dst=dstmac)/pkt
            wrpcap(out_file, pkt, append=True)
        except Exception as e:
            print(e)
            exit(1)
        
        cnt +=1

        # if cnt % 1_000_000 == 0:
        #     print("Processed %d packets..." % cnt)
        #     break

    print("Done.")

if __name__ == "__main__":
    main(sys.argv)