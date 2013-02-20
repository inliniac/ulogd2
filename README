Userspace logging daemon for netfilter/iptables

Project Homepage: http://www.gnumonks.org/projects/ulogd
Mailinglist: http://lists.gnumonks.org/mailman/listinfo/ulogd/

This is just a short README, pleaes see the more extensive documentation
in the doc/ subdirectory.

===> IDEA

This packages is intended for doing all netfilter related logging inside a
userspace process.  This includes
	- logging of ruleset violations via ipt_ULOG (kernel 2.4.18+)
	- logging of ruleset violations via nfnetlink_log (kernel 2.6.14+)
	- logging of connection startup/teardown (kernel 2.6.14+)
	- connection-based accounting  (kernel 2.6.14+)

===> CONTENTS

= ulogd daemon (ulogd)
A sophisticated logging daemon core which uses a plugin for about anything. The
daemon provides a plugin API for
	- input plugins
	- filter plugins
	- output plugins

= documentation (doc)
A quite verbose documentation of this package and it's configuration exists,
please actually make use of it and read it :)

===> USAGE

To be able to build ulogd, you need to have working developement files and
and libraries for:
 - libnfnetlink
 - libmnl
 - libnetfilter_log 		[optional]
 - libnetfilter_conntrack	[optional]
 - libnetfilter_acct		[optional]

Output plugins are build if the needed library and headers are found. This
includes:
 - PCAP: libpcap
 - PGSQL: libpq
 - MySQL: libmysqlclient
 - SQLITE3: libsqlite3
 - DBI: libdbi

The build procedure is standard:
 $ ./configure
 $ make
 $ sudo make install

After build, you need to edit the ulogd.conf file to define a stack or more
to use.

===> EXAMPLES

= NFLOG usage

At first a simple example, which passes every outgoing packet to the
userspace logging, using nfnetlink group 3.

iptables -A OUTPUT -j NFLOG --nflog-group 3

A more advanced one, passing all incoming tcp packets with destination
port 80 to the userspace logging daemon listening on netlink multicast
group 32. All packets get tagged with the ulog prefix "inp"

iptables -A INPUT -j NFLOG -p tcp --dport 80 --nflog-group 32 --nflog-prefix inp

See iptables -j NFLOG -h for complete information about NFLOG.

= NFCT usage

To use connection logging, simply activate in ulogd.conf one stack using
the NFCT plugin.

For example, the following stack will do flow-based logging via
LOGEMU:

 stack=ct1:NFCT,ip2str1:IP2STR,print1:PRINTFLOW,emu1:LOGEMU

= NFACCT usage

On ulogd side, activate a stack using the NFACCT module.

You then need to create counters:
 # nfacct add ipv4.tcp
 # nfacct add ipv6.tcp.443

Once this is done, you can then create iptables matching rule that will increment
each time a packet hit them:

 # iptables -A FORWARD -p tcp -m nfacct --nfacct-name ipv4.tcp
 # ip6tables -A FORWARD -p tcp  --dport 443 -m nfacct --nfacct-name ipv6.tcp.443
 # ip6tables -A FORWARD -p tcp  --sport 443 -m nfacct --nfacct-name ipv6.tcp.443

NFACCT plugin will then dump periodically the counters and trigger an update of the
output corresponding to the active stacks.

===> COPYRIGHT + CREDITS

The code and documentation is
	(C) 2000-2006 by Harald Welte <laforge@gnumonks.org>
	(C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>
	(C) 2008-2013 Eric Leblond <eric@regit.org>

Thanks also to the valuable contributions of Daniel Stone, Alexander Janssen,
Michael Stolovitzsky and Jozsef Kadlecsik.

Credits to Rusty Russell, James Morris, Marc Boucher and all the other
netfilter hackers.
