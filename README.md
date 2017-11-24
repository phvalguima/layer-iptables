# Overview

The charm is used to manage iptables on a machine.

# Usage

This charm is a subordinate charm. It must be attached to a another application.
All nodes of the same application it is attached to will allow ssh amongst each other.

 ```
juju deploy iptables
juju juju add-relation iptables <yourapp>
```


## Scale out Usage

Scale the application which this charm is subordinate to.


# Configuration

Make sure you allow access from your control nodes if you need ssh access for
debug purposes. By default charm autodetects control node IP addresses and allows SSH from all of them.

The 'enforce' setting can be set to set INPUT chain policy to either ACCEPT or DENY

The 'log-unmatched' setting can be set to set LOG action in the end of a rule chain created by the charm. Thih causes the iptables
to log packets unmatched by the rules into the syslog with prefix matching JUJU unit name. Logging requires access to kernel log 
infrastructure, which is not available in Linux containers.

Example ruleset:
```
     ssh:
       allow-peers: True
       allow-hosts: 
         - 10.31.148.1 
         - 10.226.148.17
       allow-networks:
         - 10.32.148.0/24 
         - 10.228.148.0/24
       protocol: tcp
       port: 22
```
Options:
 - ssh: in example above is a rule name
 - allow-peers: should peer units be able in ACCEPT rule
 - allow-hosts: list of hosts in ACCEPT rule
 - allow-networks: list of networks in ACCEPT rule
 - deny-hosts: list of hosts in DENY rule
 - deny-networks: list of networks in DENY rule
 - protocol: which protocol the rule aplies to. By default tcp
 - port: which port the rule applies to, by default taken from the rule name
 - portrange: which port range (in format start:end, eg 1:1024) the rule applies to. Takes precedence over port setting.

# Troubleshooting

If you lock yourself out from accessing machines via ssh set enforce to false and enable logging.
```
juju config iptables enforce=false
juju config iptables log-unmatched=true
```

