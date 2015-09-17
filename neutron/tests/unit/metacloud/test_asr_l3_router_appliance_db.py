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
import random
from testtools import matchers
import webob.exc as webexc

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import models_v2
from neutron.plugins.cisco.common import cisco_exceptions as cexc
from neutron.plugins.cisco.db.l3 import asr_l3_router_appliance_db as db
from neutron.tests import base
from neutron.tests.unit.metacloud import test_cfg
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import testlib_api

from oslo.config import cfg


class FakePlugin(object):
    def __init__(self):
        self.network = None

    def _get_subnet(self, context, subnet_id):
        return {'network_id': 1234, 'cidr': '10.0.0.0/24', 'ip_version': 4}

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

    @mock.patch('neutron.manager.NeutronManager.get_plugin')
    @mock.patch('neutron.plugins.cisco.db.l3.l3_router_appliance_db.'
                'L3RouterApplianceDBMixin.add_router_interface')
    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._get_or_create_SNAT_mapping')
    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._create_hsrp_interfaces')
    def test_mapping_id_created_for_router_added(self, create_hsrp,
                                                 get_mapping, add_router_if,
                                                 mock_plugin):
        """Test mapping id is added when router is added."""
        mock_plugin.return_value = FakePlugin()
        db_api = db.PhysicalL3RouterApplianceDBMixin()

        add_router_if.return_value = {'port_id': 1234, 'subnet_id': 1}

        ctx = context.get_admin_context()
        db_api.add_router_interface(ctx, '1234', {})
        get_mapping.assert_called_once_with(ctx, 1234)

    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._delete_hsrp_interfaces')
    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._delete_SNAT_mapping')
    @mock.patch('neutron.manager.NeutronManager.get_plugin')
    @mock.patch('neutron.plugins.cisco.db.l3.l3_router_appliance_db.'
                'L3RouterApplianceDBMixin.remove_router_interface')
    def test_mapping_id_deleted_for_router_deleted(self, remove_if,
                                                   mock_plugin, del_snat,
                                                   del_hsrp):
        """Test mapping id is deleted when router is deleted."""
        mock_plugin.return_value = FakePlugin()
        db_api = db.PhysicalL3RouterApplianceDBMixin()

        remove_if.return_value = {'port_id': 456, 'subnet_id': 1}
        ctx = context.get_admin_context()
        db_api.remove_router_interface(ctx, 1234, {})

        del_snat.assert_called_once_with(ctx, 456)

    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._get_or_create_SNAT_mapping')
    def test_process_sync_data(self, snat_map):
        """Test mapping id is added in the router dict."""
        db_api = db.PhysicalL3RouterApplianceDBMixin()

        vlans = [random.randint(1000, 2000), random.randint(1000, 2000),
                 random.randint(1000, 2000)]

        snat_map.side_effect = vlans

        ctx = context.get_admin_context()
        router_dict = db_api._process_sync_data(ctx, test_cfg.routers_data_1,
                                                test_cfg.interfaces_1,
                                                test_cfg.floating_ips_1)

        self.assertEqual(vlans[0],
                         router_dict[1]['_floatingips'][0]['mapping_id'])
        self.assertEqual(vlans[1],
                         router_dict[1]['_interfaces'][0]['mapping_id'])
        self.assertEqual(vlans[2],
                         router_dict[1]['_interfaces'][1]['mapping_id'])

    @mock.patch('neutron.plugins.cisco.db.l3.l3_router_appliance_db.'
                'L3RouterApplianceDBMixin.update_floatingip')
    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._get_or_create_SNAT_mapping')
    def test_mapping_id_when_floatingip_added(self, get_snat, update_fip):
        """Test mapping id generated is called when floating ip is added."""

        fip_info = {}
        fip_info['port_id'] = 123
        fip_info['floating_port_id'] = 999

        update_fip.return_value = fip_info

        db_api = db.PhysicalL3RouterApplianceDBMixin()

        ctx = context.get_admin_context()
        db_api.update_floatingip(ctx, "1", "172.10.0.12")
        get_snat.assert_called_once_with(ctx, fip_info['floating_port_id'])

    @mock.patch('neutron.plugins.cisco.db.l3.l3_router_appliance_db.'
                'L3RouterApplianceDBMixin.update_floatingip')
    @mock.patch('neutron.plugins.cisco.db.l3.asr_l3_router_appliance_db.'
                'PhysicalL3RouterApplianceDBMixin._delete_SNAT_mapping')
    def test_mapping_id_when_floatingip_deleted(self, del_snat, update_fip):
        """Test mapping id deletion is called when floating ip is deleted."""

        fip_info = {}
        fip_info['port_id'] = None
        fip_info['floating_port_id'] = 888

        update_fip.return_value = fip_info

        db_api = db.PhysicalL3RouterApplianceDBMixin()

        ctx = context.get_admin_context()
        db_api.update_floatingip(ctx, "1", "172.0.0.12")
        del_snat.assert_called_once_with(ctx, fip_info['floating_port_id'])


class TestPhysicalL3RouterApplianceDBMixinMapping(
        test_plugin.NeutronDbPluginV2TestCase):
    """Test the tracking of the SNAT mapping ids."""

    def setUp(self):
        super(TestPhysicalL3RouterApplianceDBMixinMapping, self).setUp()
        self.context = context.get_admin_context()

    def _generate_port(self):
        """Create a port (and a related network) and return the port id."""
        res = self._create_network(self.fmt, name='net1', admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        net_id = network['network']['id']
        res = self._create_port(self.fmt, net_id,
                                webexc.HTTPCreated.code)
        port = self.deserialize(self.fmt, res)
        port_id = port['port']['id']
        return port_id

    def test_init_errors_if_misconfigured(self):
        # List of (min_mapping_id, max_mapping_id) tuples.
        wrong_configs = [
            (-1, 1),
            (0, 1),
            (2 ** 31, 2 ** 31 + 1),
            (2, 2 ** 31),
            (20, 10),
        ]
        for min_mapping_id, max_mapping_id in wrong_configs:
            cfg.CONF.set_override(
                'min_mapping_id', min_mapping_id, group="metacloud")
            cfg.CONF.set_override(
                'max_mapping_id', max_mapping_id, group="metacloud")
            with testlib_api.ExpectedException(cfg.Error):
                db.PhysicalL3RouterApplianceDBMixin()

    def test_init_accepts_valid_configs(self):
        # List of (min_mapping_id, max_mapping_id) tuples.
        valid_configs = [
            (1, 2 ** 31 - 1),
            (10, 20),
            (12, 2 ** 31 - 2),
        ]
        for min_mapping_id, max_mapping_id in valid_configs:
            cfg.CONF.set_override(
                'min_mapping_id', min_mapping_id, group="metacloud")
            cfg.CONF.set_override(
                'max_mapping_id', max_mapping_id, group="metacloud")

            # No exception raised.
            db.PhysicalL3RouterApplianceDBMixin()

    def test_DB_class_supports_min_mapping_id(self):
        # The minimum mapping id (1) can be used.
        port_id = self._generate_port()
        min_mapping_id = 1
        self.assertThat(cfg.CONF.metacloud.min_mapping_id,
                        matchers.Equals(min_mapping_id))
        mapping = db.ASR1kSNATMapping(port_id=port_id,
                                      mapping_id=min_mapping_id)
        self.context.session.add(mapping)
        new_mapping = self.context.session.query(
            db.ASR1kSNATMapping).filter_by(port_id=port_id).first()
        self.assertThat(new_mapping.mapping_id,
                        matchers.Equals(min_mapping_id))

    def test_DB_class_supports_max_mapping_id(self):
        # The minimum mapping id (2 ** 31 - 1) can be used.
        port_id = self._generate_port()
        max_mapping_id = 2 ** 31 - 1
        self.assertThat(cfg.CONF.metacloud.max_mapping_id,
                        matchers.Equals(max_mapping_id))
        mapping = db.ASR1kSNATMapping(port_id=port_id,
                                      mapping_id=max_mapping_id)

        self.context.session.add(mapping)
        new_mapping = self.context.session.query(
            db.ASR1kSNATMapping).filter_by(port_id=port_id).first()
        self.assertThat(new_mapping.mapping_id,
                        matchers.Equals(max_mapping_id))

    def test_mapping_gets_deleted_when_port_gets_deleted(self):
        port_id = self._generate_port()
        mapping_id = random.randint(
            db.MIN_MAPPING_ID,
            db.MAX_MAPPING_ID + 1)
        mapping = db.ASR1kSNATMapping(port_id=port_id, mapping_id=mapping_id)
        self.context.session.add(mapping)

        self.context.session.query(
            models_v2.Port).filter_by(id=port_id).delete()

        query = self.context.session.query(
            db.ASR1kSNATMapping).filter_by(mapping_id=mapping_id)
        self.assertThat(query.all(),
                        matchers.Equals([]), "Mapping not deleted")

    def test__get_or_create_SNAT_mapping_creates_new_mapping(self):
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        port_id = self._generate_port()
        query_all = self.context.session.query(db.ASR1kSNATMapping).all()
        self.assertThat(query_all, matchers.Equals([]))
        mapping_id = router_mixin._get_or_create_SNAT_mapping(self.context,
                                                             port_id)

        query = self.context.session.query(
            db.ASR1kSNATMapping).filter_by(
                port_id=port_id, mapping_id=mapping_id)
        self.assertThat(query.one().mapping_id,
                        matchers.Equals(mapping_id), "Mapping not created")

    def test__get_or_create_SNAT_mapping_generates_sequential_mapping(self):
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        new_min_mapping_id = random.randint(
            db.MIN_MAPPING_ID,
            db.MAX_MAPPING_ID + 1 - 10)
        mapping_number = random.randint(2, 5)
        cfg.CONF.set_override(
             'min_mapping_id', new_min_mapping_id, group="metacloud")

        mapping_ids = [
            router_mixin._get_or_create_SNAT_mapping(
                self.context, self._generate_port())
            for _ in range(mapping_number)
        ]

        expected_range = range(
            new_min_mapping_id, new_min_mapping_id + mapping_number)
        self.assertThat(mapping_ids, matchers.Equals(expected_range))

    def test__get_or_create_SNAT_mapping_retrieves_existing_mapping(self):
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        port_id = self._generate_port()
        mapping_id = router_mixin._get_or_create_SNAT_mapping(self.context,
                                                             port_id)

        mapping_id2 = router_mixin._get_or_create_SNAT_mapping(self.context,
                                                              port_id)

        self.assertThat(mapping_id2, matchers.Equals(mapping_id))

    def test__get_or_create_SNAT_mapping_fills_gaps(self):
        """Gaps in the mapping id sequence are re-used."""
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        mapping_number = random.randint(3, 5)
        mapping_ids = [
            router_mixin._get_or_create_SNAT_mapping(
                self.context, self._generate_port())
            for _ in range(mapping_number)
        ]
        deleted_mapping_id = mapping_ids[mapping_number - 2]
        self.context.session.query(
            db.ASR1kSNATMapping).filter_by(
                mapping_id=deleted_mapping_id).delete()

        mapping_id = router_mixin._get_or_create_SNAT_mapping(
            self.context, self._generate_port())

        self.assertThat(mapping_id, matchers.Equals(deleted_mapping_id))

    def test__get_or_create_SNAT_mapping_errors_when_id_exhaustion(self):
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        port_id = self._generate_port()
        router_mixin._get_or_create_SNAT_mapping(self.context,
                                                port_id)
        new_max_mapping_id = 1
        cfg.CONF.set_override(
             'max_mapping_id', new_max_mapping_id, group="metacloud")

        with testlib_api.ExpectedException(cexc.MappingIDPoolExhausted):
            port_id = self._generate_port()
            router_mixin._get_or_create_SNAT_mapping(self.context,
                                                     port_id)

    def test__delete_SNAT_mapping_deletes_mapping(self):
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()
        port_id = self._generate_port()
        mapping_id = router_mixin._get_or_create_SNAT_mapping(self.context,
                                                             port_id)

        router_mixin._delete_SNAT_mapping(self.context, port_id)

        query = self.context.session.query(
            db.ASR1kSNATMapping).filter_by(
                port_id=port_id, mapping_id=mapping_id)
        self.assertThat(query.count(),
                        matchers.Equals(0), "Mapping not deleted")

    def test__delete_SNAT_mapping_ignores_non_existant_mapping(self):
        non_existant_mapping_id = random.randint(
            db.MIN_MAPPING_ID,
            db.MAX_MAPPING_ID + 1 - 10)
        router_mixin = db.PhysicalL3RouterApplianceDBMixin()

        # _delete_SNAT_mapping doesn't error when passed a non-existant
        # mapping id.
        router_mixin._delete_SNAT_mapping(
            self.context, non_existant_mapping_id)
