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
from neutron.db import db_base_plugin_v2 as plugin
from neutron.tests import base

from oslo.config import cfg


class TestNeutronDbPluginV2(base.BaseTestCase):
    @mock.patch('neutron.db.db_base_plugin_v2.'
                'NeutronDbPluginV2._get_subnets_by_network')
    def test_subnet_count_validation(self, mock_get_subnet):
        """Validate subnet count base on the metacloud options."""
        db_api = plugin.NeutronDbPluginV2()

        # Test no op if subnet_per_network is a default value (negative number)
        self.assertTrue(db_api._validate_subnet_count(None, None))

        # Test subnet count
        cfg.CONF.set_override(name='subnet_per_network',
                              override=0,
                              group='metacloud')

        # Test no op if subnet_per_network is a default value (zero)
        self.assertTrue(db_api._validate_subnet_count(None, None))

        # Test subnet count
        cfg.CONF.set_override(name='subnet_per_network',
                              override=1,
                              group='metacloud')

        # return 1 item
        mock_get_subnet.return_value = [{}]

        self.assertRaises(n_exc.InvalidInput,
                          db_api._validate_subnet_count,
                          None,
                          {'network_id': 123})

        cfg.CONF.set_override(name='subnet_per_network',
                              override=2,
                              group='metacloud')

        mock_get_subnet.return_value = [{}]
        self.assertTrue(db_api._validate_subnet_count(None,
                                                      {'network_id': 123}))

        # If network_id is not presented, don't do validation
        self.assertTrue(db_api._validate_subnet_count(None,
                                                      {'subnet_id': 456}))
