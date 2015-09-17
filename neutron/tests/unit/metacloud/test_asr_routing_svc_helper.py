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
from neutron.plugins.cisco.cfg_agent import cfg_exceptions as cfg_exc
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_snippets
from neutron.plugins.cisco.cfg_agent.service_helpers import \
    asr_routing_svc_helper as helper
from neutron.tests import base

from oslo.config import cfg


class TestPhyRouterContext(base.BaseTestCase):
    @mock.patch.object(helper.PhyRouterContext, "_get_port_set_diffs")
    @mock.patch.object(helper.PhyRouterContext, "_set_subnet_info")
    @mock.patch.object(helper.PhyRouterContext, "_internal_network_added")
    @mock.patch.object(helper.PhyRouterContext, "_routes_updated")
    @mock.patch.object(helper.PhyRouterContext, "_internal_network_removed")
    @mock.patch.object(helper.PhyRouterContext, "_external_gateway_added")
    @mock.patch.object(helper.PhyRouterContext, "_floating_ip_added")
    @mock.patch.object(helper.PhyRouterContext, "_external_gateway_removed")
    @mock.patch.object(helper.PhyRouterContext, "_set_port_status")
    def test_port_status_update(self, mock_port_status, mock_gateway,
                                mock_floating, mock_external, mock_net_remove,
                                mock_updated, mock_add, mock_info, mock_diffs):
        manager = mock.MagicMock()
        manager.attach_mock(mock_net_remove, "mock_net_remove")
        manager.attach_mock(mock_add, "mock_add")
        manager.attach_mock(mock_gateway, "mock_gateway")
        manager.attach_mock(mock_external, "mock_external")

        router = {}
        router['ha_info'] = "NA"
        router['_floatingips'] = [{'router_id': 123,
                                   'status': 'DOWN',
                                   'tenant_id': 111,
                                   'floating_network_id': 999,
                                   'fixed_ip_address': '40.0.0.6',
                                   'floating_ip_address': '30.0.0.13',
                                   'port_id': 1,
                                   'id': '4e158f98',
                                   'floating_port_id': 999,
                                   'mapping_id': 123}]
        ri = helper.RouterInfo(1234, router)
        p1 = {"id": 1}
        p2 = {"id": 2}
        p3 = {"id": 3}
        p4 = {"id": 4}
        gw_port = {"id": 5}
        ri.router['gw_port'] = gw_port

        ri.internal_ports.append(p1)
        ri.ha_gw_ports.append(p3)

        mock_diffs.side_effect = [([p1], [p2]), ([p3], [p4]),
                                  ([p1], [p2]), ([p3], [p4])]
        router_context = helper.PhyRouterContext({}, None, None, "ACTIVE")

        router_context._process_router(ri)

        ri.internal_ports.append(p1)
        ri.ha_gw_ports.append(p3)

        # Test _internal_network_added throws exception
        params = {'snippet': "NAT", 'type': "ERROR", 'tag': "ERROR_TAG"}
        mock_add.side_effect = cfg_exc.CSR1kvConfigException(**params)

        router_context._process_router(ri)
        mock_port_status.assert_has_calls([mock.call(2, 'ACTIVE'),
                                           mock.call(4, 'ACTIVE'),
                                           mock.call(999, 'ACTIVE'),
                                           mock.call(5, 'ACTIVE'),
                                           mock.call(2, 'DOWN'),
                                           mock.call(4, 'ACTIVE'),
                                           mock.call(5, 'ACTIVE')])

        # verfiy the call orders
        expected_call_orders = [mock.call.mock_net_remove(ri, {'id': 1}, None),
                                mock.call.mock_add(ri, {'id': 2}, {'id': 5}),
                                mock.call.mock_gateway(ri, {'id': 3}),
                                mock.call.mock_external(ri, {'id': 4}),
                                mock.call.mock_net_remove(ri,
                                                          {'id': 1},
                                                          {'id': 5}),
                                mock.call.mock_add(ri, {'id': 2}, {'id': 5}),
                                mock.call.mock_gateway(ri, {'id': 3}),
                                mock.call.mock_external(ri, {'id': 4})]

        self.assertEqual(manager.mock_calls, expected_call_orders)

    @mock.patch('neutron.plugins.cisco.cfg_agent.service_helpers.'
                'asr_routing_svc_helper.PhyRouterContext._set_port_status')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._check_response')
    @mock.patch('neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv.'
                'asr1k_routing_driver.ASR1kRoutingDriver._get_connection')
    def test_process_floating_ip_with_mapping_id(self, connect, resp,
                                                 set_port_status):
        """Test process floating ip calls with mapping id parameter."""
        manager = mock.MagicMock()
        manager.attach_mock(connect, "connect")

        cfg.CONF.set_override(name="use_stateful_nat", override=False,
                              group="general")

        asr_config = {'ip': '1.1.1.1', 'ssh_port': 22,
                      'username': 'cisco', 'password': 'cisco',
                      'conn': None, 'redundancy_group': 1, 'name': "r1",
                      'target_intf': 'gigabitethernet1'}
        router_context = helper.PhyRouterContext(asr_config, None, None,
                                                 "ACTIVE")
        router = {}
        router['ha_info'] = "NA"
        router['_floatingips'] = [{'router_id': '1234', 'status': 'DOWN',
                                   'tenant_id': 111,
                                   'floating_network_id': 999,
                                   'fixed_ip_address': '40.0.0.6',
                                   'floating_ip_address': '172.0.0.13',
                                   'port_id': 1, 'id': '4e158f98',
                                   'floating_port_id': 999, 'mapping_id': 909}]
        ex_gw_port = {}
        ex_gw_port["network_id"] = "989898"
        ex_gw_port["hosting_info"] = {"segmentation_id": 999}

        ri = helper.RouterInfo("1234", router)
        router_context._process_router_floating_ips(ri, ex_gw_port)

        expect_str = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH % (
            '40.0.0.6', '172.0.0.13', 'nrouter-1234-None', 1064, 999)
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target='running')
        self.assertEqual(manager.mock_calls[1], expect_call)

        cfg.CONF.set_override(name="use_stateful_nat", override=True,
                              group="general")

        ri = helper.RouterInfo("1234", router)
        router_context._process_router_floating_ips(ri, ex_gw_port)

        expect_str = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH_RG % (
            '40.0.0.6', '172.0.0.13', 'nrouter-1234-None', '1', 909)
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target='running')
        self.assertEqual(manager.mock_calls[3], expect_call)

        # removal case
        ri.floating_ips = [{'router_id': '1234', 'status': 'DOWN',
                            'tenant_id': 111,
                            'floating_network_id': 999,
                            'fixed_ip_address': '40.0.0.8',
                            'floating_ip_address': '172.0.0.99',
                            'port_id': 1, 'id': '99999',
                            'floating_port_id': 999, 'mapping_id': 909}]
        ex_gw_port = {}
        ex_gw_port["network_id"] = "989898"
        ex_gw_port["hosting_info"] = {"segmentation_id": 999}
        ri.ex_gw_port = ex_gw_port

        router_context._process_router_floating_ips(ri, ex_gw_port)
        expect_str = asr1k_snippets.REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH_RG % (
            '40.0.0.8', '172.0.0.99', 'nrouter-1234-None', '1', 909)
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target='running')
        self.assertEqual(manager.mock_calls[5], expect_call)

        expect_str = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH_RG % (
            '40.0.0.6', '172.0.0.13', 'nrouter-1234-None', '1', 909)
        expect_call = mock.call.connect().edit_config(config=expect_str,
                                                      target='running')
        self.assertEqual(manager.mock_calls[7], expect_call)
