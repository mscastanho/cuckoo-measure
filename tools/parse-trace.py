#! /usr/bin/env python3
import argparse
import sys
from scapy.all import *
import tqdm
import time
import csv

# This class tracks a flow, storing the 
# following paremeters
#   - Last pkt timestamp (last seen)
#   - Pkt count
#   - Sum of interarrival times

class Tracker(object):
    last_seen = 0
    count = 0
    tsum = 0

    def __init__(self,timestamp):
        self.last_seen = timestamp
        self.count = 1 
        self.tsum = 0
    
    def __str__(self):
        return "Pkt count: %d\tAvg interrival: %f s" % (self.count,self.avg_interarrival())

    def avg_interarrival(self):
        return self.tsum/self.count

def get_5tuple(pkt):
    if not IP in pkt:
        return None
    else:
        ipsrc = pkt[IP].src
        ipdst = pkt[IP].dst

        proto = int(pkt[IP].proto)
        
        if proto == 6: # TCP
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif proto == 17: # UDP
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            sport = 0
            dport = 0

    return (ipsrc,ipdst,sport,dport,proto)
        
        
def main(argv):
    parser = argparse.ArgumentParser(prog=argv[0],description='Calculates interarrival time for all flows in a pcap file')
    
    parser.add_argument('-f', '--file', metavar='<trace file>', 
        help='Path to packet trace file', required=True)

    parser.add_argument('-c', '--csv', action='store_const', const=True,
        default=False,help='Output results as csv file')

    parser.add_argument('-p', '--print', action='store_const', const=True,
        default=False,help='Output results to stdout')

    args = vars(parser.parse_args())

    output_csv = args['csv']
    output_stdout = args['print'] 
    filename = args['file']

    flows = {}

    cnt = 0
    start_time = time.time()
    PKT_CNT_LIMIT = 10_000
    FLOW_MIN_PKTS = 100
    out_file = "selected_flows_%s_%s.pcap" % (PKT_CNT_LIMIT,FLOW_MIN_PKTS)
    for pkt in PcapReader(filename):
        # print("ipsrc: %s\tipdst: %s\tproto: %s" % (pkt[IP].src,pkt[IP].src,pkt[IP].proto))
        try:
            t = get_5tuple(pkt)
        except Exception as e:
            # print("Error: %s" % str(e))
            # print(pkt.summary())
            continue


        if not t in flows:
            flows[t] = Tracker(pkt.time)
        else:
            tkr = flows[t]
            tkr.count += 1
            tkr.tsum += pkt.time - tkr.last_seen
            tkr.last_seen = pkt.time
        # print("[%.6f]\t%s" % (pkt.time,str(t)))
        cnt += 1
        if cnt > PKT_CNT_LIMIT:
            break

    selected = {}
    if output_csv:
        csvfile = open("trace_summary_%s_%s.csv" % (PKT_CNT_LIMIT,FLOW_MIN_PKTS),"w")
        colnames = ['IP src','IP dst','Protocol','Src port','Dst port','Packet count','Average interarrival']
        writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_NONNUMERIC)
        # writer.writeheader()
        writer.writerow(colnames)

    for f in flows:
        tk = flows[f]
        if tk.count > FLOW_MIN_PKTS:
            selected[f] = tk.avg_interarrival()
            if output_csv:
                writer.writerow(list(f)+[tk.count,"%.6f" % tk.avg_interarrival()])
            if output_stdout:
                print("%s\t:\t%s" % (f,flows[f]))

    cntsel = 0
    cnt = 0
    # Create new pcap only with packets from selected flows
    with PcapWriter(out_file) as pw:
        for pkt in PcapReader(filename):
            try:
                t = get_5tuple(pkt)
            except Exception as e:
                # print("Error: %s" % str(e))
                # print(pkt.summary())
                continue
            
            if t in selected:
                cntsel += 1
                pw.write(pkt)
            
            cnt += 1
            if cnt > PKT_CNT_LIMIT:
                break
                
    time_elapsed = time.time() - start_time
    print("\n\n# of pkts: %d\n# of flows: %d" % (cnt,len(flows)))
    print("# of selected pkts: %d\n# of selected flows: %d" % (cntsel,len(selected)))
    print("Time elapsed: %f" % time_elapsed)

if __name__ == "__main__":
    main(sys.argv)