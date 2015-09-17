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

import ciscoconfparse
import mock

from ncclient import manager
from neutron.common import constants
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_cfg_syncer
from neutron.tests import base
from neutron.tests.unit.metacloud import test_cfg


class TestConfigSyncer(base.BaseTestCase):
    def setUp(self):
        super(TestConfigSyncer, self).setUp()
        self.syncer = asr1k_cfg_syncer.ConfigSyncer(
            {}, "qqq", ["id1", "id2"], "R1", "Te0/0/0")

    @mock.patch('ncclient.manager.connect')
    def test_clean_nat_pool_overload_with_empty_conf(self, mock_connect):
        '''Test nat_pool config is destructed correctly

        This test also tests when everything is deleted from the router and
        the function doesn't crash
        '''
        conn = manager.connect()
        parsed_cfg = ciscoconfparse.CiscoConfParse(
            test_cfg.test_config_sample1)
        self.syncer.clean_nat_pool_overload(
            conn, {'dec967': []}, {1000: []}, {1000: False}, parsed_cfg)
        expected_conf = '<config>' \
                        '<cli-config-data><cmd>' \
                        'no ip nat inside source list neutron_acl_qqq_1001 ' \
                        'pool nrouter-dec967-qqq_nat_pool vrf ' \
                        'nrouter-dec967-qqq overload' \
                        '</cmd></cli-config-data></config>'
        conn.edit_config.assert_called_once_with(target='running',
                                                 config=expected_conf)

    @mock.patch('ncclient.manager.connect')
    def test_clean_rg_interface_valid_internal_net(self, mock_connect):
        """Test redundancy group config with valid internal interface."""
        parsed_sub_if = ciscoconfparse.CiscoConfParse(test_cfg.sub_if_1)
        sub_if = parsed_sub_if.find_objects("GigabitEthernet2.1001")
        sub_if[0].segment_id = 1001
        sub_if[0].is_external = False
        sub_if_dict = [
            {'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
             'fixed_ips': [{'ip_address': '60.0.0.1'}]}
        ]
        ret = self.syncer.clean_interface_ipv4_rg_check(
            sub_if[0], {1001: sub_if_dict})
        self.assertTrue(
            ret, "Expect clean_interface_ipv4_rg_check return True on "
                 "valid internal interface config")

    @mock.patch('ncclient.manager.connect')
    def test_clean_rg_interface_invalid_internal_net(self, mock_connect):
        """Test redundancy group config with valid internal interface.

        Neutron port is 60.0.0.8 while config in the router is 60.0.0.1
        """
        parsed_sub_if = ciscoconfparse.CiscoConfParse(test_cfg.sub_if_1)
        sub_if = parsed_sub_if.find_objects("GigabitEthernet2.1001")
        sub_if[0].segment_id = 1001
        sub_if[0].is_external = False
        incorrect_if_dict = [
            {'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
             'fixed_ips': [{'ip_address': '60.0.0.8'}]}
        ]
        ret = self.syncer.clean_interface_ipv4_rg_check(
            sub_if[0], {1001: incorrect_if_dict})
        self.assertFalse(
            ret, "Expect clean_interface_ipv4_rg_check return False on "
                 "invalid internal interface config")

    @mock.patch('ncclient.manager.connect')
    def test_clean_rg_interface_valid_external_net(self, mock_connect):
        """Test redundancy group config with valid external interface."""
        parsed_sub_ex_if = ciscoconfparse.CiscoConfParse(test_cfg.sub_ex_if_1)
        sub_ex_if = parsed_sub_ex_if.find_objects("GigabitEthernet2.1000")
        sub_ex_if[0].segment_id = 1000
        sub_ex_if[0].is_external = True
        sub_ex_if_dict = [
            {'device_id': "PHYSICAL_GLOBAL_ROUTER_ID",
             'device_owner': constants.DEVICE_OWNER_ROUTER_GW,
             'fixed_ips': [{'ip_address': '31.0.0.1'}]}
        ]
        ret = self.syncer.clean_interface_ipv4_rg_check(
            sub_ex_if[0], {1000: sub_ex_if_dict})
        self.assertTrue(
            ret, "Expect clean_interface_ipv4_rg_check return True on "
                 "valid external interface config")

    @mock.patch('ncclient.manager.connect')
    def test_clean_rg_interface_invalid_external_net(self, mock_connect):
        """Test redundancy group config with invalid external interface.

        Neutron port is 31.0.0.8 while config in the router is 31.0.0.1
        """
        parsed_sub_ex_if = ciscoconfparse.CiscoConfParse(test_cfg.sub_ex_if_1)
        sub_ex_if = parsed_sub_ex_if.find_objects("GigabitEthernet2.1000")
        sub_ex_if[0].segment_id = 1000
        sub_ex_if[0].is_external = True
        incorrect_ex_if_dict = [
            {'device_id': "PHYSICAL_GLOBAL_ROUTER_ID",
             'device_owner': constants.DEVICE_OWNER_ROUTER_GW,
             'fixed_ips': [{'ip_address': '31.0.0.8'}]}
        ]
        ret = self.syncer.clean_interface_ipv4_rg_check(
            sub_ex_if[0], {1000: incorrect_ex_if_dict})
        self.assertFalse(
            ret, "Expect clean_interface_ipv4_rg_check return False on "
                 "Neutron port IP and VIP mismatch")

    @mock.patch('ncclient.manager.connect')
    def test_clean_rg_interface_invalid_rii(self, mock_connect):
        """Test redundancy group config with invalid rii.

        Vlan ID and RII value are mismatch
        """
        incorrect_vlan_if = (
            ciscoconfparse.CiscoConfParse(test_cfg.wrong_sub_if_1))
        vlan_if = incorrect_vlan_if.find_objects("GigabitEthernet2.1001")

        ret = self.syncer.clean_interface_ipv4_rg_check(
            vlan_if[0], {})
        self.assertFalse(
            ret, "Expect clean_interface_ipv4_rg_check return False on "
                 "VLAN and RII mismatch")

    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_cfg_syncer.ConfigSyncer.clean_interfaces_nat_check')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_cfg_syncer.ConfigSyncer.clean_interfaces_ipv4_check')
    @mock.patch('ncclient.manager.connect')
    def test_cleaning_invalid_interface(
            self, mock_connect, nat_check, ip_check):
        """Test clean_interfaces actually delete interface when rg interface
        is invalid.

        """
        manager = mock.MagicMock()
        manager.attach_mock(mock_connect, "mock_connect")
        nat_check.return_value = True
        ip_check.return_value = True
        syncer = asr1k_cfg_syncer.ConfigSyncer(
            {}, "qqq", ["id1", "id2"], "R1", "GigabitEthernet2")
        parsed_sub_ex_if = ciscoconfparse.CiscoConfParse(test_cfg.sub_ex_if_1)
        sub_ex_if = parsed_sub_ex_if.find_objects("GigabitEthernet2.1000")
        sub_ex_if[0].segment_id = 1000
        sub_ex_if[0].is_external = True
        sub_ex_if_dict = [
            {'device_id': "PHYSICAL_GLOBAL_ROUTER_ID",
             'device_owner': constants.DEVICE_OWNER_ROUTER_GW,
             'subnet': {'cidr': '31.0.0.0/24'},
             'network_id': '1234',
             'fixed_ips': [{'ip_address': '31.0.0.8'}]}
        ]
        syncer.clean_interfaces(
            mock_connect, {1000: sub_ex_if_dict}, {1000: None},
            parsed_sub_ex_if)

        del_cmd = asr1k_cfg_syncer.XML_CMD_TAG % (
            "no interface GigabitEthernet2.1000")
        expect_str = asr1k_cfg_syncer.XML_FREEFORM_SNIPPET % (del_cmd)
        expect_call = mock.call.mock_connect.edit_config(
            config=expect_str, target='running')

        self.assertEqual(expect_call, manager.mock_calls[0])
