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
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_cfg_syncer
from neutron.tests import base
from neutron.tests.unit.metacloud import test_cfg


class TestConfigSyncer(base.BaseTestCase):
    @mock.patch('ncclient.manager.connect')
    def test_clean_nat_pool_overload_with_empty_conf(self, mock_connect):
        '''Test nat_pool config is destructed correctly

        This test also tests when everything is deleted from the router and
        the function doesn't crash
        '''

        syncer = asr1k_cfg_syncer.ConfigSyncer({}, "qqq", ["id1", "id2"],
                                               "R1", "Te0/0/0")

        conn = manager.connect()
        parsed_cfg = ciscoconfparse.CiscoConfParse(
            test_cfg.test_config_sample1)
        syncer.clean_nat_pool_overload(conn, {'dec967': []}, {1000: []},
                                       {1000: False},
                                       parsed_cfg)
        expected_conf = '<config>' \
                        '<cli-config-data><cmd>' \
                        'no ip nat inside source list neutron_acl_qqq_1001 ' \
                        'pool nrouter-dec967-qqq_nat_pool vrf ' \
                        'nrouter-dec967-qqq overload' \
                        '</cmd></cli-config-data></config>'
        conn.edit_config.assert_called_once_with(target='running',
                                                 config=expected_conf)
