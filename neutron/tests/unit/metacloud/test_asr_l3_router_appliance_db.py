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

from neutron.common import exceptions as n_exc
from neutron.plugins.cisco.db.l3 import asr_l3_router_appliance_db as db
from neutron.tests import base

from oslo.config import cfg


class FakePlugin(object):
    def __init__(self):
        self.network = None

    def _get_subnet(self, context, subnet_id):
        return {'network_id': 1234, 'cidr': '10.0.0.0/24'}

    def _get_network(self, context, subnet_id):
        return self.network

    def _get_port(self, context, port_id):
        return {'network_id': 1234}

    def _set_network(self, data):
        self.network = data


class TestPhysicalL3RouterApplianceDBMixin(base.BaseTestCase):
    @mock.patch('neutron.manager.NeutronManager.get_plugin')
    def test_external_network_as_internal_interface(self, mock_plugin):
        """Test external_network_as_internal_interface flag."""
        fake_plugin = FakePlugin()
        fake_plugin._set_network({"external": None})
        mock_plugin.return_value = fake_plugin
        db_api = db.PhysicalL3RouterApplianceDBMixin()

        # Test default behavior
        db_api._validate_router_interface(None, None)

        cfg.CONF.set_override(name="external_net_as_internal_if",
                              override=False,
                              group="metacloud")

        # subnet case, internal network
        db_api._validate_router_interface(None, {'subnet_id': 1234})

        # subnet case, external network
        fake_plugin._set_network({"external": True})
        self.assertRaises(n_exc.BadRequest,
                          db_api._validate_router_interface,
                          None,
                          {'subnet_id': 1234})

        fake_plugin = FakePlugin()
        fake_plugin._set_network({"external": None})
        mock_plugin.return_value = fake_plugin
        # port case, internal network
        db_api._validate_router_interface(None, {'port_id': 1234})

        # port case, external network
        fake_plugin._set_network({"external": True})
        self.assertRaises(n_exc.BadRequest,
                          db_api._validate_router_interface,
                          None,
                          {'port_id': 1234})

    @mock.patch('neutron.manager.NeutronManager.get_plugin')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.get_routers')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                '_check_for_dup_router_subnet')
    def test_internal_if_on_multi_router(self, mock_dup, mock_router,
                                         mock_routers, mock_plugin):
        """Test internal_net_on_multiple_routers flag."""
        fake_plugin = FakePlugin()
        fake_plugin._set_network({"external": None, "shared": False})
        mock_plugin.return_value = fake_plugin
        db_api = db.PhysicalL3RouterApplianceDBMixin()

        db_api._validate_router_interface(None, None)

        cfg.CONF.set_override(name="internal_net_on_multiple_routers",
                              override=False,
                              group="metacloud")

        mock_routers.return_value = [{"id": 1}, {"id": 3}]

        # test normal case
        db_api._validate_router_interface(None, {"subnet_id": 1234})

        self.assertEqual(mock_dup.call_count, 2)

        # test throw exception
        mock_dup.side_effect = n_exc.BadRequest(resource='router',
                                                msg="Testing...")
        self.assertRaises(n_exc.BadRequest,
                          db_api._validate_router_interface,
                          None,
                          {"subnet_id": 1234})
