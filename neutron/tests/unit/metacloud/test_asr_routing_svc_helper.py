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
from neutron.plugins.cisco.cfg_agent.service_helpers import \
    asr_routing_svc_helper as helper
from neutron.tests import base


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
                                   'floating_port_id': 999}]
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
