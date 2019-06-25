#!/usr/bin/python3

from mock import (
    patch,
    Mock,
)
import yaml
import unittest
from reactive.iptables import (
    setup_nat,
    iptables_start
)

TEST_ADD_NAT_RULE_YAML="""- PREROUTING:
  - dst: 192.168.0.1
  - dport: 80
  - protocol: tcp
  - DNAT:
    - to-destination: 127.0.0.1:8080
"""
class TestCharm(unittest.TestCase):

    @patch('reactive.iptables.log',
           Mock(return_value=""))
    @patch('reactive.iptables.status_set',
           Mock(return_value=""))
    @patch('reactive.iptables.set_state',
           Mock(return_value=""))
    @patch('reactive.iptables.data_changed',
           Mock(return_value=""))
    @patch('reactive.iptables.get_peers',
           Mock(return_value=""))
    @patch('reactive.iptables.get_controllers',
           Mock(return_value=""))
    @patch('reactive.iptables.controllers_set_name',
           Mock(return_value=""))
    @patch('reactive.iptables.peers_set_name',
           Mock(return_value=""))
    @patch('reactive.iptables.controllers_set_name',
           Mock(return_value=""))
    @patch('reactive.iptables.local_unit',
           Mock(return_value="loc-unit"))
    @patch('reactive.iptables.hookenv.config')
    @patch('reactive.iptables.call')
    def test_run_iptables_start_with_nat_only(self,
                                              mock_call,
                                              mock_config):
        mock_config.return_value = {"nat": TEST_ADD_NAT_RULE_YAML}
        iptables_start()
        # TODO: define which assert to use here
        
    @patch('reactive.iptables.log',
           Mock(return_value=""))
    @patch('reactive.iptables.hookenv.config')
    @patch('reactive.iptables.call')
    def test_add_nat_rule(self,
                          mock_call,
                          mock_config):
        mock_config.return_value = {"nat": TEST_ADD_NAT_RULE_YAML}
        setup_nat()
        mock_call.assert_called_once_with(
            'iptables -t nat -A PREROUTING --dst 192.168.0.1 --dport 80 '
            '--protocol tcp'
            ' -j DNAT --to-destination 127.0.0.1:8080',
            shell = True)



if __name__ == '__main__':
    unittest.main()
