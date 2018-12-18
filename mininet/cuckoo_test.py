#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from subprocess import call

from eBPFSwitch import eBPFSwitch, eBPFHost

from time import sleep

class SingleSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1',
            switch_path="../softswitch/softswitch")

        for h in xrange(2): #TODO number of hosts
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.0.%d/24" % (1+h),
                                mac = '00:04:00:00:00:%02x' %h)

            self.addLink(host, switch)

def monitorTest( N=3, seconds=3 ):
    "Run pings and monitor multiple hosts"
    topo = SingleSwitchTopo( N )
    net = Mininet( topo )
    net.start()
    

def main():
    print "Starting test..."

    # App parameters
    windows = [10] # in ms
    slots = [8]
    intervals = [5,1,0.5,0.1,0.05,0.01,0.005,0.001] # in ms
    count = 20

    for w in windows:
        for s in slots:
            for i in intervals:
                topo = SingleSwitchTopo()
                net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)
                net.start()

                hosts = net.hosts

                h1 = hosts[0]
                h2 = hosts[1]
                
                # Init background traffic
                #h2.cmd('iperf3 -s')
                #h1.cmdPrint('iperf3','-c',h2.IP(),'-u','-t','0','-b','10k')
                
                print "Waiting config from controller..."
                sleep(2)

                outfile="perf_%f_%d_%f.out" % (w,s,i)

                print "Starting test with W=%f S=%d I=%f" % (w,s,i)

                h2.cmd("iperf3-3.6 -s > srv-%s &" % outfile)
                print "Started iperf3 server"

                # Start iperf
                h1.cmdPrint('iperf3-3.6',
                            '-c', h2.IP(),
                            '-u',
                            '-t', 20,
                            '--pacing-timer',i*1000,
                            '>', "cli-%s" % outfile,
                            '&')

                sleep(1.5)
                CLI(net)
                net.stop()
                #h1.cmd('pkill iperf3')
                call("../tools/copy-out-files.sh")
            
    print "Done!"


if __name__ == '__main__':
    main()
