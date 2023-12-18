#!/usr/bin/python

import os
import sys
import glob

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI

script_deps = ['ethtool', 'arptables', 'iptables']


def check_scripts():
    dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    for fname in glob.glob(dir + '/' + 'scripts/*.sh'):
        if not os.access(fname, os.X_OK):
            print('%s should be set executable by using `chmod +x $script_name`' % (fname))
            sys.exit(1)

    for program in script_deps:
        found = False
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
                found = True
                break
        if not found:
            print('`%s` is required but missing, which could be installed via `apt` or `aptitude`' % (program))
            sys.exit(2)


class TCPTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, h2, delay='10ms')


if __name__ == '__main__':
    check_scripts()

    topo = TCPTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)

    h1, h2 = net.get('h1', 'h2')
    for h in (h1, h2):
        h.cmd('scripts/disable_ipv6.sh')
        h.cmd('scripts/disable_offloading.sh')
        h.cmd('scripts/disable_tcp_rst.sh')

#    h1.cmd('python3 ./tcp_stack_trans.py server 10001 2 &')
    h1.cmd('./tcp_stack server 10001 2> server_log.txt &')
    h2.cmd('./tcp_stack client 10.0.0.1 10001 2> client_log.txt &')

#    h1.cmd('python3 ./tcp_stack_trans.py server 10001 2 &')
#    h2.cmd('python3 ./tcp_stack_trans.py client 10.0.0.1 10001 &')

    net.start()
    CLI(net)
    net.stop()
