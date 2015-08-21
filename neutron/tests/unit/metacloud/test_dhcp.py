# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.agent import dhcp_agent
from neutron.agent.linux import dhcp
from neutron.common import constants
from neutron.tests import base

from oslo.config import cfg


class FakeIP(object):
    def __init__(self, ip, subnet_id):
        self.ip_address = ip
        self.subnet_id = subnet_id


class FakePort(object):
    def __init__(self, ips, subnet_id):
        self.fixed_ips = ips
        self.subnet_id = subnet_id
        self.device_owner = constants.DEVICE_OWNER_ROUTER_INTF


class FakeSubnet(object):
    def __init__(self, id, gw):
        self.id = id
        self.gateway_ip = gw


class FakeNetwork(object):
    def __init__(self):
        self.subnets = []
        self.ports = []


class TestDnsmasq(base.BaseTestCase):
    def test_force_isolated_subnet(self):
        """This test is to test the force_isolated flag

        If it is False, all the subnet will be treated as isolated subnet
        If it is True, isolated_subnet logic will be retained as upstream
        """
        dhcp_agent.register_options()

        # Test force_isolated = True
        cfg.CONF.set_override(name='force_isolated',
                              override=True,
                              group='metacloud')
        network = FakeNetwork()

        network.subnets = [FakeSubnet('1', '10.0.0.1'),
                           FakeSubnet('2', '11.0.0.1'),
                           FakeSubnet('3', '12.0.0.1')]

        network.ports = [FakePort([FakeIP('10.0.0.1', '1')], '1'),
                         FakePort([FakeIP('11.0.0.1', '2')], '2'),
                         FakePort([FakeIP('12.0.0.1', '3')], '3')]
        isolated_sub = dhcp.Dnsmasq.get_isolated_subnets(network)

        self.assertTrue(isolated_sub['1'])
        self.assertTrue(isolated_sub['2'])
        self.assertTrue(isolated_sub['3'])

        # default dict should return anything as True
        self.assertTrue(isolated_sub['4'])

        # Test force_isolated = False
        cfg.CONF.set_override(name='force_isolated',
                              override=False,
                              group='metacloud')

        isolated_sub = dhcp.Dnsmasq.get_isolated_subnets(network)

        self.assertFalse(isolated_sub['1'])
        self.assertFalse(isolated_sub['2'])
        self.assertFalse(isolated_sub['3'])

        # default dict should return anything as True
        self.assertTrue(isolated_sub['4'])