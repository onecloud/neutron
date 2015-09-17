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

import mock

from neutron.common import constants
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_routing_driver
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_snippets
from neutron.tests import base

from oslo.config import cfg


class TestASR1kRoutingDriver(base.BaseTestCase):
    def setUp(self):
        super(TestASR1kRoutingDriver, self).setUp()
        self.asr_config = {'ip': '1.1.1.1', 'ssh_port': 22,
                           'username': 'cisco', 'password': 'cisco',
                           'conn': None, 'redundancy_group': 1, 'name': "r1"}
        self.driver = asr1k_routing_driver.ASR1kRoutingDriver(self.asr_config)

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('ncclient.manager.connect')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_csr_add_redundancy_group')
    def test_nat_rules_with_rg_option(self, create_sub_if, connect, resp):
        """Test setting nat rules with redundancy group."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")

        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "mapping_id": 1,
                "device_owner": "router_interface"}
        self.driver._csr_create_subinterface(None, port, True)
        create_sub_if.assert_called_with_once(None, port, "", True)

        self.driver._nat_rules_for_internet_access("1", None, "255.255.255.0",
                                                   "Gb1", "Gb2", "vrf1",
                                                   "vlan1", "vlan2", port)

        expected_str = asr1k_snippets.SET_DYN_SRC_TRL_POOL_RG % (
            "1", "vrf1_nat_pool", "1", "1", "vrf1")
        expected_call = mock.call.connect().edit_config(config=expected_str,
                                                        target='running')
        self.assertEqual(expected_call, manager.mock_calls[2])

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('ncclient.manager.connect')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_csr_add_ha_HSRP')
    def test_nat_rules_with_hsrp_option(self, create_sub_if, connect, resp):
        """Test setting nat rules with HSRP."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")

        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")
        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "mapping_id": 1,
                "device_owner": "router_interface"}
        self.driver ._csr_create_subinterface(None, port, True)
        create_sub_if.assert_called_with_once(None, port, "", True)

        self.driver ._nat_rules_for_internet_access("1", None, "255.255.255.0",
                                                    "Gb1", "Gb2", "vrf1",
                                                    "vlan1", "vlan2", port)

        expected_str = asr1k_snippets.SET_DYN_SRC_TRL_POOL % (
            "1", "vrf1_nat_pool", "vrf1")
        expected_call = mock.call.connect().edit_config(config=expected_str,
                                                        target='running')
        self.assertEqual(expected_call, manager.mock_calls[2])

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_port_needs_config')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_csr_get_vrf_name')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_get_interface_name_from_hosting_port')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_get_interface_vlan_from_hosting_port')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('ncclient.manager.connect')
    def test_add_redundancy_group(self, connect, resp, get_vlan, get_if,
                                  get_vrf, need_cfg):
        """Test _csr_add_redundancy_group calling logic."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")
        need_cfg.return_value = True
        get_vlan.return_value = 123
        get_if.return_value = "Gb1"
        get_vrf.return_value = "vrf1"

        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "mapping_id": 1,
                "device_owner": "network:router_ha_gateway"}

        self.driver ._csr_add_redundancy_group(port, "1234", "1.1.1.1", None,
                                               True)

        self.driver ._csr_add_redundancy_group(port, "1234", "1.1.1.1", None,
                                               False)

        expect_string = asr1k_snippets.SET_ASR_REDUNDANCY_GROUP_EXTERNAL % (
            "Gb1", 123, 1, "1.1.1.1")
        expect_call = mock.call.connect().edit_config(config=expect_string,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[1])

        expect_string = asr1k_snippets.SET_ASR_REDUNDANCY_GROUP_INTERNAL % (
            "Gb1", "vrf1", 123, 1, "1.1.1.1")
        expect_call = mock.call.connect().edit_config(config=expect_string,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[4])

    def test_valid_check_for_stateful_nat(self):
        """Test config is valid for stateful nat."""
        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "mapping_id": 1,
                "device_owner": "network:router_ha_gateway"}
        self.assertTrue(
            self.driver._is_config_valid_for_stateful_nat(port)
        )

        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "device_owner": "network:router_ha_gateway"}
        self.assertFalse(
            self.driver ._is_config_valid_for_stateful_nat(port)
        )

        driver = asr1k_routing_driver.ASR1kRoutingDriver(
            {'ip': '1.1.1.1', 'ssh_port': 22, 'username': 'cisco',
             'password': 'cisco', 'conn': None, 'name': "r1"})
        port = {"ip_cidr": "10.0.0.0/24",
                "fixed_ips": [{"ip_address": "10.0.0.1"}],
                "mapping_id": 1,
                "device_owner": "network:router_ha_gateway"}
        self.assertFalse(driver ._is_config_valid_for_stateful_nat(port))

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('ncclient.manager.connect')
    def test_add_floating_ip_config(self, connect, resp):
        """Test floating IP to static NAT translation."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")

        ex_port = {}
        ex_port["hosting_info"] = {"segmentation_id": 100}

        self.driver._add_floating_ip("172.16.0.4", "10.0.0.10", "vrf1", "grp",
                                     ex_port, "908")

        expect_str = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH_RG % (
            "10.0.0.10", "172.16.0.4", "vrf1", "1", "908"
        )
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[1])
        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")

        self.driver._add_floating_ip("172.16.0.4", "10.0.0.10", "vrf1", "grp",
                                     ex_port, "908")
        expect_str = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH % (
            "10.0.0.10", "172.16.0.4", "vrf1", "grp", "100")
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[4])

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('ncclient.manager.connect')
    def test_remove_floating_ip_config(self, connect, resp):
        """Test remove floating ip command statement."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")

        ex_port = {}
        ex_port["hosting_info"] = {"segmentation_id": 100}

        self.driver._remove_floating_ip("172.16.0.4", "10.0.0.10", "vrf1",
                                        "grp", ex_port, "908")

        expect_str = asr1k_snippets.REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH_RG % (
            "10.0.0.10", "172.16.0.4", "vrf1", "1", "908"
        )
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[1])

        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")

        self.driver._remove_floating_ip("172.16.0.4", "10.0.0.10", "vrf1",
                                        "grp", ex_port, "908")

        expect_str = asr1k_snippets.REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH % (
            "10.0.0.10", "172.16.0.4", "vrf1", "grp", "100"
        )
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target="running")
        self.assertEqual(expect_call, manager.mock_calls[4])

    def test_port_valid_for_stateful_nat_config(self):
        """Test what port type is valid for stateful nat config."""
        port = {}
        port['phy_router_db'] = self.asr_config['name']
        port['device_owner'] = constants.DEVICE_OWNER_ROUTER_INTF

        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")
        self.assertFalse(self.driver._is_config_valid_for_internal_nat(port))

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")
        self.assertTrue(self.driver._is_config_valid_for_internal_nat(port))

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver.'
                '_nat_rules_for_internet_access')
    def test_nat_setup_with_invalid_port(self, nat_call):
        """Test port is not eligbile to create nat rules."""
        port = {}
        port['phy_router_db'] = self.asr_config['name']
        port['device_owner'] = constants.DEVICE_OWNER_ROUTER_INTF

        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")
        self.assertEqual(0, nat_call.call_count)

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")
        port['device_owner'] = constants.DEVICE_OWNER_ROUTER_HA_GW
        self.assertEqual(0, nat_call.call_count)
