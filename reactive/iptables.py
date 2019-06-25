from charms.reactive import (
    when,
    when_not,
    when_any,
    set_state,
    remove_state,
    RelationBase,
    hook
)
from charms.reactive.bus import (
    get_states
)
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    related_units,
    local_unit,
    relation_ids,
    relation_get,
    log,
    status_set,
    config,
    in_relation_hook,
    execution_environment
)
from charms.reactive.helpers import data_changed, is_state
from subprocess import call
from charmhelpers.contrib.network.ip import get_iface_addr
from charmhelpers.contrib.network.ip import is_address_in_network
from netifaces import interfaces
import time
import yaml
import six
from jinja2 import Environment

@when_not('iptables.installed')
def install_iptables_charm():
    set_state('iptables.installed')


@when_any('host-system.available', 'host-system.connected')
@when('iptables.installed')
@when_not('iptables.started')
def iptables_start():
    log('Starting firewall')
    status_set('maintenance', 'Setting up IPTables')
    set_state('iptables.started') 


    data_changed('controllers', [])
    data_changed('peers', [])

    ipset_create(peers_set_name(), 'hash:ip')
    hosts = get_peers()
    ipset_update(peers_set_name() , hosts)
    ipset_create(controllers_set_name(), 'hash:ip')
    controllers = get_controllers()
    ipset_update(controllers_set_name(), controllers)
    status_set('maintenance', 'setting all rules now')
    setup_chain()
    setup_rules()
    setup_policy()
    setup_nat()
    status_set('active', 'Policy: %s' % get_policy_name() )

@when('config.changed.nat')
def nat_changed():
    if not is_state('iptables.started'):
        iptables_start()
    status_set('maintenance', 'Setting up NAT Table')
    setup_nat()
    status_set('active', 'ready' )

    
def setup_nat():
    """
    Expect something similar to:

      - prerouting: # chain
          - dst: 192.168.0.1
          - dport: 80
          - p: tcp
          - DNAT:
            - to-destination: IP:PORT
      - prerouting: # chain
          - dst: 192.168.0.1
          - dport: 443
          - protocol: udp
          - DNAT:
            - to-destination: IP:PORT
    """
    def replace_tmpl(value):
        # Building here rather than using get_all_addresses
        # because we need to return a dict and specifically,
        # ifaces need to have: "interface:NAME" format
        # Therefore, not very useful for rest of the code
        addresses = {}
        for iface in interfaces():
            for addr in get_iface_addr(iface=iface,
                                       inc_aliases=True,
                                       fatal=False):
                addresses["interface_{}".format(iface)] = addr
        env = Environment()
        t = env.from_string(str(value))
        # For the moment, we only replace interface names
        return t.render(**addresses)

    nat_rules = yaml.load(hookenv.config()["nat"])
    for n in nat_rules:
        cmd = []
        nat_found = False
        for chain_name in n:
            chain = n[chain_name]  # should be iteritems for py3
            # Grabbing first part of the rule:
            cmd = ['iptables','-t','nat','-A',chain_name]
            for option in chain:
                if option.get('DNAT'):
                    nat_found = True
                    cmd.extend(['-j','DNAT'])
                    for nat_config in option['DNAT']:
                        for k,v in six.iteritems(nat_config):
                            # str(v) avoids port to convert to int
                            cmd.extend(['--{}'.format(k), replace_tmpl(v)])
                elif option.get('SNAT'):
                    nat_found = True
                    cmd.extend(['-j','SNAT'])
                    for nat_config in option['SNAT']:
                        for k,v in six.iteritems(nat_config):
                            # str(v) avoids port to convert to int
                            cmd.extend(['--{}'.format(k), replace_tmpl(v)])
                else:
                    for k,v in six.iteritems(option):
                        # str(v) avoids port to convert to int
                        cmd.extend(['--{}'.format(k), replace_tmpl(v)])

        # Now, grab the jump_config:
        if not nat_found:
            raise TypeError("NAT config must contain either DNAT or "
                            "SNAT definition, in capital letters")
        log("Running rule: {}".format(' '.join(cmd)))
        call(' '.join(cmd), shell = True)

def get_enforce():
    config = hookenv.config()
    return config.get('enforce')

def get_log_unmatched():
    config = hookenv.config()
    return config.get('log-unmatched')

def get_policy_name():
    if get_enforce():
      if get_log_unmatched():
        return "LOG,DROP"
      return "DROP"
    else:
      if get_log_unmatched():
        return "LOG,ACCEPT"
      return "ACCEPT"

def filter_name():
    return "%s-filter" % local_unit()

def controllers_set_name():
    uname,uid = local_unit().split("/")
    return "juju-%s-%s" % ( uname[:8], uid )

def peers_set_name():
    uname,uid = local_unit().split("/")
    return "peers-%s-%s" % ( uname[:8], uid )
    
def allow_hosts_set_name(service):
    uname,uid = local_unit().split("/")
    return "h-%s-%s-%s" % ( uname[:8], uid, service[:16] )

def allow_networks_set_name(service):
    uname,uid = local_unit().split("/")
    return "n-%s-%s-%s" % ( uname[:8], uid, service[:16] )

def deny_hosts_set_name(service):
    uname,uid = local_unit().split("/")
    return "dh-%s-%s-%s" % ( uname[:8], uid, service[:16] )

def deny_networks_set_name(service):
    uname,uid = local_unit().split("/")
    return "dn-%s-%s-%s" % ( uname[:8], uid, service[:16] )

def setup_chain():
    call('iptables -N %s'%filter_name(), shell=True)
    call('iptables -t filter -A INPUT -j %s'%filter_name(), shell=True)

def flush_chain():
    call('iptables -t filter -D INPUT -j %s'%filter_name(), shell=True)
    call('iptables -X %s'%filter_name(), shell=True)

def get_port_config(rule_config):
    if rule_config['protocol']=='icmp':
      return ""
    if 'portrange' in rule_config:
      return "-m multiport --dports %s" % rule_config['portrange']
    else:
      return "--dport %s" % rule_config['port']
    
def setup_policy():
    if get_enforce() == None:
        log("setup_policy: enforce not defined, will not set it")
        return
    if get_enforce():
        setup_policy_drop()
        set_state('enforce')
    else:
        setup_policy_accept()
        remove_state('enforce')

def setup_rules():
    if get_ruleset() == None:
        # Case where I only want to set NAT, not filters
        log("setup_rules: No ruleset defining, returning")
        return
    flush_rules()
    log('Enabling rules')
    call('iptables -A %s --match state --state ESTABLISHED,RELATED -j ACCEPT'%filter_name(), shell=True)
    call('iptables -A %s -p tcp --dport ssh -m set --match-set %s src -j ACCEPT' % ( filter_name(), controllers_set_name() ), shell=True)
    for service in get_ruleset():
      rule_config=get_ruleset()[service]
      if not 'protocol' in rule_config:
        rule_config['protocol']='tcp'
      if not 'port' in rule_config:
        rule_config['port']=service
      if not 'allow-peers' in rule_config:
        rule_config['allow-peers']=False
      if not 'allow-hosts' in rule_config:
        rule_config['allow-hosts']=[]
      if not 'allow-networks' in rule_config:
        rule_config['allow-networks']=[]
      if not 'deny-hosts' in rule_config:
        rule_config['deny-hosts']=[]
      if not 'deny-networks' in rule_config:
        rule_config['deny-networks']=[]
      ipset_create( allow_hosts_set_name(service) , 'hash:ip')
      ipset_update( allow_hosts_set_name(service), rule_config['allow-hosts'])
      ipset_create( allow_networks_set_name(service), 'hash:net')
      ipset_update( allow_networks_set_name(service), rule_config['allow-networks'])
      ipset_create( deny_hosts_set_name(service) , 'hash:ip')
      ipset_update( deny_hosts_set_name(service), rule_config['deny-hosts'])
      ipset_create( deny_networks_set_name(service), 'hash:net')
      ipset_update( deny_networks_set_name(service), rule_config['deny-networks'])
      if rule_config['allow-peers']:
        call('iptables -A %s -p %s %s -m set --match-set %s src -j ACCEPT'%( filter_name(), rule_config['protocol'], get_port_config(rule_config), peers_set_name() ), shell=True)

      if rule_config['deny-networks']:
        call('iptables -A %s -p %s %s -m set --match-set %s src -j DROP  '%( filter_name(), rule_config['protocol'], get_port_config(rule_config), deny_networks_set_name(service) ), shell=True)
      if rule_config['deny-hosts']:
        call('iptables -A %s -p %s %s -m set --match-set %s src -j DROP  '%( filter_name(), rule_config['protocol'], get_port_config(rule_config), deny_hosts_set_name(service)), shell=True)

      if rule_config['allow-networks']:
        call('iptables -A %s -p %s %s -m set --match-set %s src -j ACCEPT'%( filter_name(), rule_config['protocol'], get_port_config(rule_config), allow_networks_set_name(service) ), shell=True)
      if rule_config['allow-hosts']:
        call('iptables -A %s -p %s %s -m set --match-set %s src -j ACCEPT'%( filter_name(), rule_config['protocol'], get_port_config(rule_config), allow_hosts_set_name(service)), shell=True)

    if get_log_unmatched():
      log("Enabling logging")
      call('iptables -A %s -m limit --limit 1/second -j LOG --log-prefix "%s unmatched:" --log-level 4' %( filter_name(), local_unit() ), shell=True)

def flush_rules():
    log('Flushing rules')
    call('iptables -F %s'%filter_name(), shell=True)

def setup_policy_drop():
    log('Setting policy to DROP')
    call('iptables --policy INPUT DROP', shell=True)  

def setup_policy_accept():
    log('Setting policy to ACCEPT')
    call('iptables --policy INPUT ACCEPT', shell=True)  

def flush_policy():
    log('Flushing policy')
    call('iptables --policy INPUT ACCEPT', shell=True)
    remove_state('enforcing')
    remove_state('enforce')

@when_not('enforcing')
@when('enforce')
def enforce():
    setup_policy_drop()
    set_state('enforcing')

@when('enforcing')
@when_not('enforce')
def not_enforce():
    setup_policy_accept()
    remove_state('enforcing')

@hook('stop')
def iptables_stop():
    log('Stopping firewall')
    status_set('maintenance', 'Stopping IPTables')
    flush_policy()
    flush_rules()
    flush_chain()
    ipset_destroy(peers_set_name())
    ipset_destroy(controllers_set_name())
    for service in get_ruleset():
      ipset_destroy( allow_hosts_set_name(service) )
      ipset_destroy( allow_networks_set_name(service) )
    remove_state('iptables.started')
    status_set('maintenance', 'Stopped')

@hook('config-changed')
def config_changed():
    if not ipset_exists( controllers_set_name() ):
      log("ipset %s missng, restarting" % controllers_set_name()  )
      iptables_stop()
      iptables_start() 

@hook('upgrade-charm')
def upgrade_charm():
    iptables_stop()
    iptables_start()

@hook('update-status')
def update_status():
    log("States %s"%get_states() )
    log("Env %s"% execution_environment()  )
    controllers = get_controllers()
    if data_changed('controllers', controllers):
        ipset_update(controllers_set_name(), controllers)

def get_ruleset():
    if hookenv.config().get('ruleset') == None:
        return None
    ruleset=yaml.load(hookenv.config()['ruleset'])
    if ruleset is None:
       ruleset=[]
    return ruleset


def get_all_addresses():
    addresses = []
    for iface in interfaces():
        if not iface == 'lo':
            for addr in get_iface_addr(iface=iface, inc_aliases=True, fatal=False):
                addresses.append(addr)
    return addresses


def get_all_remote_addresses(peers):
    addresses = []
    for conv in peers.conversations():
        conv_remotes_map=conv.get_remote('addresses')
        log("Adding all private remote addresses: %s"%conv_remotes_map)
        if not conv_remotes_map is None:
          for addr in conv_remotes_map.split(" "):
            addresses.append(addr)
    return addresses


@when('peers.joined')
def connected(peers):
    log("peers.joined %s"%peers.units() )
    config = hookenv.config()
    addresses = get_all_addresses()
    peers.set_remote('addresses', ' '.join(addresses))
    if is_state('iptables.started'):
        hosts = get_peers()
        if data_changed('peers', hosts):
            ipset_update(peers_set_name(), hosts)



@when('peers.departed')
def departed(peers):
    log("peers.departed %s"%peers.units() )
    if is_state('iptables.started'):
        hosts = get_peers()
        if data_changed('peers', hosts):
            ipset_update(peers_set_name(), hosts)



@when('config.changed.ruleset')
def ruleset_changed():
    if not is_state('iptables.started'):
        iptables_start()
    status_set('maintenance', 'Setting up IPTables')
    setup_rules()
    setup_policy()
    status_set('active', 'Policy: %s' % get_policy_name() )
           
@when('config.changed.enforce')
def change_enforce():
    setup_policy()


@when('config.changed.use-private-addresses')
def change_use_private():
    hosts = get_peers()
    ipset_update(peers_set_name(), hosts)


@when('config.changed.filter-peers-by-networks')
def change_use_private():
    hosts = get_peers()
    ipset_update(peers_set_name(), hosts)

@when('config.changed.log-unmatched')
def change_log_unmatched():
    ruleset_changed()

def ipset_exists(name):
    return call(['ipset', 'list', name, '-name' ])==0

def ipset_create(name, type):
    if name == None:
        log("ipset_create: returning as name is None")
        return
    log("ipset_create %s" % name)
    call(['ipset', 'create',  "%s" % ( name), type, '-exist' ] )
    call(['ipset', 'create',  "%s-tmp" % ( name), type, '-exist' ])

def ipset_destroy(name):
    log("ipset_destroy %s" % name)
    call(['ipset', 'destroy',  "%s" % ( name)])
    call(['ipset', 'destroy',  "%s-tmp" % ( name)])

def ipset_update(name, hosts):
    log("Updating {} ipset".format(name))
    tmpname = "%s-tmp" % ( name)
    realname = "%s" % ( name)
    call(['ipset', 'flush', tmpname])
    if not hosts is None:
      for host in hosts:
        log("Adding {} to ipset {}".format(host, tmpname))
        call(['ipset', 'add', tmpname, host])
    call(['ipset', 'swap', tmpname, realname])
    call(['ipset', 'flush', tmpname])
    log("swapped ipset {}".format(name))


def get_peers():
    hosts = []
    config = hookenv.config()
    for rel_id in relation_ids('peers'):
        for unit in related_units(rel_id):
            if config['use-private-addresses']:
                hosts.append(relation_get('private-address', unit, rel_id))
            else:
                addresses = relation_get('addresses', unit, rel_id)
                if addresses is None:
                    continue
                for addr in str(addresses).split(" "):
                    hosts.append(addr)
    filtered_networks = get_filter_peers_by_networks(config)
    if filtered_networks:
        hosts = list(filter(lambda addr: is_filtered(addr, filtered_networks), hosts))
    return hosts


def get_filter_peers_by_networks(config):
    return config['filter-peers-by-networks'].split()


def is_filtered(address, networks):
    found = False
    for net in networks:
        if is_address_in_network(net, address):
            found = True
            break
    return found

def get_controllers():
    controllers = []
    for endpoint in execution_environment()['env']['JUJU_API_ADDRESSES'].split(" "):
      ip,port=endpoint.split(':')
      controllers.append(ip)
    return controllers

