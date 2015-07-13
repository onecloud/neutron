# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import contextlib
import copy

import mock
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import uuidutils
from webob import exc

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants
from neutron.common import test_lib
from neutron import context as n_context
from neutron.extensions import agent
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.db.l3 import ha_db
from neutron.plugins.cisco.db.scheduler import (
    l3_routertype_aware_schedulers_db as router_sch_db)
from neutron.plugins.cisco.extensions import ha
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.extensions import routertypeawarescheduler
from neutron.plugins.cisco.l3.rpc import l3_router_rpc_cfg_agent_api
from neutron.plugins.common import constants as plugin_consts
from neutron.tests import fake_notifier
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.plugins.cisco.device_manager import (
    device_manager_test_support)
from neutron.tests.unit.plugins.cisco.device_manager import (
    test_db_device_manager)
from neutron.tests.unit.plugins.cisco.l3 import l3_router_test_support
from neutron.tests.unit.plugins.cisco.l3 import test_db_routertype
from neutron.tests.unit.plugins.cisco.l3 import test_l3_router_appliance_plugin
from neutron.tests.unit.plugins.openvswitch import test_agent_scheduler
from neutron.tests.unit.scheduler import test_l3_agent_scheduler

LOG = logging.getLogger(__name__)


CORE_PLUGIN_KLASS = device_manager_test_support.CORE_PLUGIN_KLASS
L3_PLUGIN_KLASS = (
    'neutron.tests.unit.plugins.cisco.l3.test_l3_routertype_aware_schedulers.'
    'TestSchedulingCapableL3RouterServicePlugin')
HA_L3_PLUGIN_KLASS = ('neutron.tests.unit.plugins.cisco.l3.'
                      'test_l3_routertype_aware_schedulers.'
                      'TestSchedulingHACapableL3RouterServicePlugin')

_uuid = uuidutils.generate_uuid
HOSTING_DEVICE_ATTR = routerhostingdevice.HOSTING_DEVICE_ATTR


class TestSchedulingL3RouterApplianceExtensionManager(
        test_db_routertype.L3TestRoutertypeExtensionManager):

    def get_resources(self):
        # first, add auto_schedule and share_hosting_device attributes to
        # router resource
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            routertypeawarescheduler.EXTENDED_ATTRIBUTES_2_0['routers'])
        # most of the resources are added in our super class
        res = super(TestSchedulingL3RouterApplianceExtensionManager,
                    self).get_resources()
        # add the router to hosting device scheduler resources
        ext_mgr = routertypeawarescheduler.Routertypeawarescheduler()
        for item in ext_mgr.get_resources():
            res.append(item)
        return res


# A scheduler-enabled routertype capable L3 routing service plugin class
class TestSchedulingCapableL3RouterServicePlugin(
    l3_router_test_support.TestL3RouterServicePlugin,
        router_sch_db.L3RouterTypeAwareSchedulerDbMixin):

    supported_extension_aliases = [
        "router", routertype.ROUTERTYPE_ALIAS,
        routertypeawarescheduler.ROUTERTYPE_AWARE_SCHEDULER_ALIAS,
        constants.L3_AGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        self.agent_notifiers.update(
            {constants.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI(),
             c_const.AGENT_TYPE_L3_CFG:
             l3_router_rpc_cfg_agent_api.L3RouterCfgAgentNotifyAPI(self)})
        self.router_scheduler = importutils.import_object(
            cfg.CONF.routing.router_type_aware_scheduler_driver)
        self.l3agent_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)


class L3RoutertypeAwareL3AgentSchedulerTestCase(
    test_l3_agent_scheduler.L3SchedulerTestCase,
    test_db_routertype.RoutertypeTestCaseMixin,
    test_db_device_manager.DeviceManagerTestCaseMixin,
    l3_router_test_support.L3RouterTestSupportMixin,
        device_manager_test_support.DeviceManagerTestSupportMixin):

    resource_prefix_map = (test_db_device_manager.TestDeviceManagerDBPlugin
                           .resource_prefix_map)

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin}

        cfg.CONF.set_override('api_extensions_path',
                              l3_router_test_support.extensions_path)
        if ext_mgr is None:
            ext_mgr = TestSchedulingL3RouterApplianceExtensionManager()

        # call grandparent's setUp() to avoid that wrong plugin and
        # extensions are used.
        super(test_l3_agent_scheduler.L3SchedulerTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self._define_keystone_authtoken()
        cfg.CONF.set_override('default_router_type',
                              c_const.NAMESPACE_ROUTER_TYPE, group='routing')

        self.adminContext = n_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_consts.L3_ROUTER_NAT)
        # work-around to make some tests in super class, which assumes core
        # plugin does the l3 routing, run correctly
        self.plugin.router_scheduler = (
            self.l3_plugin.l3agent_scheduler)
        self._register_l3_agents()
        self._mock_l3_admin_tenant()
        templates = self._test_create_hosting_device_templates()
        self._test_create_routertypes(templates.values())

    def tearDown(self):
        self._test_remove_routertypes()
        self._test_remove_hosting_device_templates()
        super(L3RoutertypeAwareL3AgentSchedulerTestCase, self).tearDown()

    def get_unscheduled_routers_only_returns_namespace_routers(self):
        self._create_mgmt_nw_for_tests(self.fmt)
        arg_list = (routertype.TYPE_ATTR, )
        kwargs = {routertype.TYPE_ATTR: test_db_routertype.HW_ROUTERTYPE_NAME}
        # router 1
        self._make_router(self.fmt, _uuid(), 'router1', arg_list=arg_list,
                          **kwargs)['router']
        # namespace-based routers
        with contextlib.nested(self.router(name='router2'),
                               self.router(name='router3')) as (
                router2, router3):
            r2 = router2['router']
            r3 = router3['router']
            # router 4
            self._make_router(self.fmt, _uuid(), 'router2', arg_list=arg_list,
                              **kwargs)['router']
            routers = self.l3_plugin.router_scheduler.get_unscheduled_routers(
                self.adminContext, self.l3_plugin)
            r_ids = set(r['id'] for r in routers)
            self.assertEqual(len(r_ids), 2)
            for r in [r2, r3]:
                self.assertIn(r['id'], r_ids)
        self._remove_mgmt_nw_for_tests()

    def test_only_namespace_routers_scheduled_by_l3agent_scheduler(self):
        self._create_mgmt_nw_for_tests(self.fmt)
        arg_list = (routertype.TYPE_ATTR, )
        kwargs = {routertype.TYPE_ATTR: test_db_routertype.HW_ROUTERTYPE_NAME}
        r1 = self._make_router(self.fmt, _uuid(), 'router1',
                               arg_list=arg_list, **kwargs)['router']
        # namespace-based routers
        with contextlib.nested(
            self.router(name='router2'), self.router(name='router3'),
            mock.patch.object(self.l3_plugin.l3agent_scheduler,
                              'schedule'),
            mock.patch('neutron.scheduler.l3_agent_scheduler.L3Scheduler.'
                       'get_routers_can_schedule')) as (
                router2, router3, scheduler_mock, auto_scheduler_mock):
            r2 = router2['router']
            r3 = router3['router']
            r4 = self._make_router(self.fmt, _uuid(), 'router4',
                                   arg_list=arg_list, **kwargs)['router']
            r_list = [r1, r2, r3, r4]
            # first test schedule function
            self.l3_plugin.schedule_routers(self.adminContext, r_list)
            scheduler_mock.assert_has_calls(
                [mock.call(mock.ANY, self.adminContext, r2['id'], None),
                 mock.call(mock.ANY, self.adminContext, r3['id'], None)])
            r_ids = [r['id'] for r in r_list]
            # then test auto_schedule function
            self.l3_plugin.auto_schedule_routers(self.adminContext, 'host_1',
                                                 r_ids)
            r_ids_scheduled = set([r['id'] for r in
                                   auto_scheduler_mock.call_args[0][2]])
            self.assertEqual(len(r_ids_scheduled), 2)
            for r in [r2, r3]:
                self.assertIn(r['id'], r_ids_scheduled)
        self._remove_mgmt_nw_for_tests()

    def test_rpc_sync_routers_gets_only_namespace_routers(self):
        self._create_mgmt_nw_for_tests(self.fmt)
        arg_list = (routertype.TYPE_ATTR, )
        kwargs = {routertype.TYPE_ATTR: test_db_routertype.HW_ROUTERTYPE_NAME}
        # router 1
        self._make_router(self.fmt, _uuid(), 'router1', arg_list=arg_list,
                          **kwargs)['router']
        # namespace-based routers
        with contextlib.nested(self.router(name='router2'),
                               self.router(name='router3')) as (
                router2, router3):
            r2 = router2['router']
            r3 = router3['router']
            # router 4
            self._make_router(self.fmt, _uuid(), 'router2', arg_list=arg_list,
                              **kwargs)['router']
            routers = self.l3_plugin.get_sync_data(self.adminContext)
            r_ids = set(r['id'] for r in routers)
            self.assertEqual(len(r_ids), 2)
            for r in [r2, r3]:
                self.assertIn(r['id'], r_ids)
        self._remove_mgmt_nw_for_tests()

    def test_check_ports_exist_on_l3agent_with_dhcp_enabled_subnets(self):
        # overload to disable this test that fails as as it pertains to DVR
        # which we don't support
        pass


class L3RoutertypeAwareChanceL3AgentSchedulerTestCase(
    test_l3_agent_scheduler.L3AgentChanceSchedulerTestCase,
        L3RoutertypeAwareL3AgentSchedulerTestCase):

    def test_scheduler_auto_schedule_when_agent_added(self):
        # in our test setup the auto_schedule_routers function is provided by
        # the separate l3 service plugin, not the core plugin
        self.plugin.auto_schedule_routers = (
            self.l3_plugin.auto_schedule_routers)
        super(L3RoutertypeAwareChanceL3AgentSchedulerTestCase,
              self).test_scheduler_auto_schedule_when_agent_added()


class L3RoutertypeAwareLeastRoutersL3AgentSchedulerTestCase(
    test_l3_agent_scheduler.L3AgentLeastRoutersSchedulerTestCase,
        L3RoutertypeAwareL3AgentSchedulerTestCase):

    def setUp(self):
        cfg.CONF.set_override('router_scheduler_driver',
                              'neutron.scheduler.l3_agent_scheduler.'
                              'LeastRoutersScheduler')
        # call grandparent's setUp() to avoid that wrong scheduler is used
        super(test_l3_agent_scheduler.L3AgentLeastRoutersSchedulerTestCase,
              self).setUp()


#TODO(bobmel): Activate unit tests for DVR when we support DVR

class RouterHostingDeviceSchedulerTestMixIn(
        test_agent_scheduler.AgentSchedulerTestMixIn):

    def _list_routers_hosted_by_hosting_device(self, hosting_device_id,
                                               expected_code=exc.HTTPOk.code,
                                               admin_context=True):
        path = "/dev_mgr/hosting_devices/%s/%s.%s" % (
            hosting_device_id, routertypeawarescheduler.DEVICE_L3_ROUTERS,
            self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_hosting_devices_hosting_router(self, router_id,
                                             expected_code=exc.HTTPOk.code,
                                             admin_context=True):
        path = "/routers/%s/%s.%s" % (
            router_id, routertypeawarescheduler.L3_ROUTER_DEVICES, self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _add_router_to_hosting_device(self, hosting_device_id, router_id,
                                      expected_code=exc.HTTPCreated.code,
                                      admin_context=True):
        path = "/dev_mgr/hosting_devices/%s/%s.%s" % (
            hosting_device_id, routertypeawarescheduler.DEVICE_L3_ROUTERS,
            self.fmt)
        req = self._path_create_request(path,
                                        {'router_id': router_id},
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)

    def _remove_router_from_hosting_device(
            self, hosting_device_id, router_id,
            expected_code=exc.HTTPNoContent.code, admin_context=True):
        path = "/dev_mgr/hosting_devices/%s/%s/%s.%s" % (
            hosting_device_id, routertypeawarescheduler.DEVICE_L3_ROUTERS,
            router_id, self.fmt)
        req = self._path_delete_request(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)


class L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase(
    test_l3.L3NatTestCaseMixin,
    RouterHostingDeviceSchedulerTestMixIn,
        test_l3_router_appliance_plugin.L3RouterApplianceTestCaseBase):

    router_type = 'ASR1k_Neutron_router'
    configure_routertypes = False

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        # save possible test_lib.test_config 'config_files' dict entry so we
        # can restore it after tests since we will change its value
        self._old_config_files = copy.copy(test_lib.test_config.get(
            'config_files'))
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        if ext_mgr is None:
            ext_mgr = TestSchedulingL3RouterApplianceExtensionManager()
        super(L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase, self).setUp(
            core_plugin, l3_plugin, dm_plugin, ext_mgr)
        # include config files for device manager service plugin and router
        # service plugin since we define a number of hosting device templates,
        # hosting devices and routertypes there
        self._add_device_manager_plugin_ini_file()
        self._add_router_plugin_ini_file()
        #TODO(bobmel): Fix bug in test_extensions.py and we can remove the
        # below call to setup_config()
        self.setup_config()
        # do pool management in same green thread during tests
        self._mock_eventlet_greenpool_spawn_n()
        # set a very long processing interval and instead call the
        # _process_backlogged_routers function directly in the tests
        cfg.CONF.set_override('backlog_processing_interval', 100,
                              group='routing')
        self.adminContext = n_context.get_admin_context()
        # tests need a predictable random.choice so we always return first
        # item in the argument sequence
        self.random_patch = mock.patch('random.choice')
        random_mock = self.random_patch.start()
        random_mock.side_effect = lambda seq: seq[0]

    def tearDown(self):
        self.random_patch.stop()
        if self._old_config_files is None:
            test_lib.test_config.pop('config_files', None)
        else:
            test_lib.test_config['config_files'] = self._old_config_files
        self._test_remove_all_hosting_devices()
        super(L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase,
              self).tearDown()


class L3RoutertypeAwareHostingDeviceSchedulerBaseTestCase(
        L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase):

    def test_new_router_backlogged_and_remains_backlogged_if_no_hosting_device(
            self):
        with contextlib.nested(
            mock.patch.object(self.plugin, '_backlogged_routers'),
            mock.patch.object(self.plugin, '_refresh_router_backlog',
                              False)) as (m1, m2):
            back_log = set()
            m1.__iter__ = lambda obj: iter(copy.deepcopy(back_log))
            m1.__contains__ = lambda obj, r_id: r_id in back_log
            m1.add.side_effect = lambda r_id: back_log.add(r_id)
            m1.discard.side_effect = lambda r_id: back_log.discard(r_id)
            arg_list = (routertype.TYPE_ATTR, )
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000007'}
            router = self._make_router(self.fmt, _uuid(), 'router1',
                                       arg_list=arg_list, **kwargs)
            r = router['router']
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            # verify that the new router is backlogged
            m1.add.assert_called_once_with(r['id'])
            self.assertIn(r['id'], back_log)
            self.plugin._process_backlogged_routers()
            # verify that the router remains backlogged since not hosting
            # device exists for the router type
            self.assertIn(r['id'], back_log)

    def test_backlogged_router_is_scheduled_if_hosting_device_exists(self):
        with contextlib.nested(
            mock.patch.object(self.plugin, '_backlogged_routers'),
            mock.patch.object(self.plugin, '_refresh_router_backlog',
                              False)) as (m1, m2):
            back_log = set()
            # o'boy, this __iter__ mock took me so long to figure out....
            m1.__iter__ = lambda obj: iter(copy.deepcopy(back_log))
            m1.__contains__ = lambda obj, r_id: r_id in back_log
            m1.add.side_effect = lambda r_id: back_log.add(r_id)
            m1.discard.side_effect = lambda r_id: back_log.discard(r_id)
            arg_list = (routertype.TYPE_ATTR, )
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000006'}
            router = self._make_router(self.fmt, _uuid(), 'router1',
                                       arg_list=arg_list, **kwargs)
            r = router['router']
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            m1.add.assert_called_once_with(r['id'])
            self.plugin._process_backlogged_routers()
            self.assertNotIn(r['id'], back_log)

    def test_already_backlogged_router_not_backlogged(self):
        with mock.patch.object(self.plugin, '_backlogged_routers') as m:
            back_log = set()
            m.__contains__.side_effect = lambda r_id: r_id in back_log
            m.add.side_effect = lambda r_id: back_log.add(r_id)
            with self.router() as router:
                r = router['router']
                self.assertIsNone(r[HOSTING_DEVICE_ATTR])
                m.add.assert_called_once_with(r['id'])
                r_after = self._update(
                    'routers', r['id'],
                    {'router': {'name': 'routerA'}})['router']
                self.assertEqual(r_after['name'], 'routerA')
                self.assertIsNone(
                    r_after[HOSTING_DEVICE_ATTR])
                # router should be back-logged only once for later
                # scheduling attempts
                m.add.assert_called_once_with(r['id'])
                m.__contains__.assert_has_calls([mock.call(r['id']),
                                                 mock.call(r['id'])])

    def test_namespace_router_not_backlogged(self):
        with mock.patch.object(self.plugin, '_backlogged_routers') as m:
            back_log = set()
            m.__contains__.side_effect = lambda r_id: r_id in back_log
            m.add.side_effect = lambda r_id: back_log.add(r_id)
            arg_list = (routertype.TYPE_ATTR, )
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000001'}
            router = self._make_router(self.fmt, _uuid(), 'router1',
                                       arg_list=arg_list, **kwargs)
            r = router['router']
            self.assertEqual(m.add.called, False)
            self.assertEqual(m.__contains__.called, False)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            r_after = self._update('routers', r['id'],
                                   {'router': {'name': 'routerA'}})['router']
            self.assertEqual(r_after['name'], 'routerA')
            self.assertIsNone(
                r_after[HOSTING_DEVICE_ATTR])
            # router should be back-logged only once for later
            # scheduling attempts
            self.assertEqual(m.add.called, False)
            self.assertEqual(m.__contains__.called, False)

    def test_router_without_auto_schedule_not_backlogged(self):
        with mock.patch.object(self.plugin, '_backlog_router') as (
                mock_b_lg):
            arg_list = (routertypeawarescheduler.AUTO_SCHEDULE_ATTR, )
            kwargs = {
                routertypeawarescheduler.AUTO_SCHEDULE_ATTR: False}
            router = self._make_router(self.fmt, _uuid(), 'router1',
                                       arg_list=arg_list, **kwargs)
            r = router['router']
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            mock_b_lg.assert_has_calls([])
            r_after = self._update('routers', r['id'],
                                   {'router': {'name': 'routerA'}})['router']
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])
            mock_b_lg.assert_has_calls([])
            self.plugin._sync_router_backlog()
            self.assertEqual(len(self.plugin._backlogged_routers), 0)

    def test_rpc_sync_routers_ext_gets_no_namespace_routers(self):
        arg_list = (routertype.TYPE_ATTR, )
        kwargs = {routertype.TYPE_ATTR: test_db_routertype.NS_ROUTERTYPE_NAME}
        # namespace-based routers
        self._make_router(self.fmt, _uuid(), 'router1', arg_list=arg_list,
                          **kwargs)
        # hw routers
        with contextlib.nested(self.router(name='router2'),
                               self.router(name='router3')) as (r2, r3):
            # router 4
            self._make_router(self.fmt, _uuid(), 'router4', arg_list=arg_list,
                              **kwargs)
            routers = self.plugin.get_sync_data_ext(self.adminContext)
            r_ids = set(r['id'] for r in routers)
            self.assertEqual(len(r_ids), 2)
            for r in [r2['router'], r3['router']]:
                self.assertIn(r['id'], r_ids)


class L3RoutertypeAwareHostingDeviceSchedulerTestCase(
        L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase):

    def test_router_add_to_hosting_device(self):
        with self.router() as router:
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertEqual(r_after[HOSTING_DEVICE_ATTR],
                             '00000000-0000-0000-0000-000000000001')

    def test_hosted_router_add_to_hosting_device(self):
        with self.router() as router:
            # trigger scheduling of router
            self.plugin._process_backlogged_routers()
            r = self._show('routers', router['router']['id'])['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNotNone(r[HOSTING_DEVICE_ATTR])
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000002', r['id'],
                exc.HTTPConflict.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertEqual(r_after[HOSTING_DEVICE_ATTR],
                             r[HOSTING_DEVICE_ATTR])

    def test_hosted_router_add_to_different_type_hosting_device(self):
        with self.router() as router:
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            hd_id = '00000000-0000-0000-0000-000000000004'
            self._add_router_to_hosting_device(hd_id, r['id'])
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[HOSTING_DEVICE_ATTR],
                             hd_id)
            temp_rt_id = '00000000-0000-0000-0000-000000000006'
            routertype_id = "%s (normal: %s)" % (temp_rt_id, rt_id)
            self.assertEqual(r_after[routertype.TYPE_ATTR], routertype_id)

    def test_router_add_to_hosting_device_insufficient_slots(self):
        with contextlib.nested(
            mock.patch.object(self.core_plugin,
                              'acquire_hosting_device_slots'),
                self.router()) as (acquire_mock, router):
            acquire_mock.return_value = False
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            hd_id = '00000000-0000-0000-0000-000000000004'
            self._add_router_to_hosting_device(hd_id, r['id'],
                                               exc.HTTPConflict.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)

    def test_router_add_to_hosting_device_insufficient_slots_no_auto(self):
        with contextlib.nested(
            mock.patch.object(self.core_plugin,
                              'acquire_hosting_device_slots'),
            mock.patch.object(self.plugin, '_backlog_router')) as (
                acquire_mock, mock_b_lg):
            acquire_mock.return_value = False
            arg_list = (routertypeawarescheduler.AUTO_SCHEDULE_ATTR, )
            kwargs = {
                routertypeawarescheduler.AUTO_SCHEDULE_ATTR: False}
            router = self._make_router(self.fmt, _uuid(), 'router1',
                                       arg_list=arg_list, **kwargs)
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            mock_b_lg.assert_has_calls([])
            hd_id = '00000000-0000-0000-0000-000000000004'
            self._add_router_to_hosting_device(hd_id, r['id'],
                                               exc.HTTPConflict.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            mock_b_lg.assert_has_calls([])

    def test_router_add_to_hosting_device_with_admin_state_down(self):
        with self.router() as router:
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            id_hd_disabled = '00000000-0000-0000-0000-000000000001'
            self._update('hosting_devices', id_hd_disabled,
                         {'hosting_device': {'admin_state_up': False}})
            self._add_router_to_hosting_device(id_hd_disabled, r['id'],
                                               exc.HTTPNotFound.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])

    def test_router_add_to_hosting_device_two_times(self):
        with self.router() as router:
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertEqual(r_after[HOSTING_DEVICE_ATTR],
                             '00000000-0000-0000-0000-000000000001')
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            r_final = self._show('routers', r['id'])['router']
            self.assertEqual(r_final[routertype.TYPE_ATTR], rt_id)
            self.assertEqual(r_final[HOSTING_DEVICE_ATTR],
                             '00000000-0000-0000-0000-000000000001')

    def test_router_remove_from_hosting_device(self):
        with self.router() as router:
            # trigger scheduling of router
            self.plugin._process_backlogged_routers()
            r = self._show('routers', router['router']['id'])['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNotNone(r[HOSTING_DEVICE_ATTR])
            self._remove_router_from_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])

    def test_router_remove_from_wrong_hosting_device(self):
        with self.router() as router:
            # trigger scheduling of router
            self.plugin._process_backlogged_routers()
            r = self._show('routers', router['router']['id'])['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNotNone(r[HOSTING_DEVICE_ATTR])
            self._remove_router_from_hosting_device(
                '00000000-0000-0000-0000-000000000002', r['id'],
                exc.HTTPConflict.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertEqual(r_after[HOSTING_DEVICE_ATTR],
                             r[HOSTING_DEVICE_ATTR])

    def test_unhosted_router_remove_from_hosting_device(self):
        with self.router() as router:
            r = router['router']
            rt_id = '00000000-0000-0000-0000-000000000005'
            self.assertEqual(r[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r[HOSTING_DEVICE_ATTR])
            self._remove_router_from_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'],
                exc.HTTPConflict.code)
            r_after = self._show('routers', r['id'])['router']
            self.assertEqual(r_after[routertype.TYPE_ATTR], rt_id)
            self.assertIsNone(r_after[HOSTING_DEVICE_ATTR])

    def test_router_scheduling_policy(self):
        with contextlib.nested(self.router(), self.router()) as (router1,
                                                                 router2):
            r1 = router1['router']
            r2 = router2['router']
            hd_id = '00000000-0000-0000-0000-000000000001'
            self._add_router_to_hosting_device(hd_id, r1['id'])
            self._list_routers_hosted_by_hosting_device(hd_id)
            self._list_routers_hosted_by_hosting_device(
                hd_id, expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._add_router_to_hosting_device(
                hd_id, r2['id'], expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._remove_router_from_hosting_device(
                hd_id, r1['id'], expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._remove_router_from_hosting_device(hd_id, r1['id'])
            self._list_hosting_devices_hosting_router(r1['id'])
            self._list_hosting_devices_hosting_router(
                r1['id'], expected_code=exc.HTTPForbidden.code,
                admin_context=False)

    def test_hosting_device_keep_services_off(self):
        #TODO(bobmel): Implement this unit test
        # Introduce new option: keep_services_on_agents_with_admin_state_down
        # Here set to keep_services_on_agents_with_admin_state_down = False
        # routers on hosting device that is set to admin down should be removed
        #  from that hosting device
        pass

    def test_hosting_device_keep_services_on(self):
        #TODO(bobmel): Implement this unit test
        # Introduce new option: keep_services_on_agents_with_admin_state_down
        # Here set to keep_services_on_agents_with_admin_state_down = False
        # routers on hosting device that set to admin down should stay on that
        # hosting device
        pass

    def test_list_routers_by_hosting_device(self):
        with contextlib.nested(self.router(),
                               self.router(),
                               self.router()) as (router1, router2, router3):
            r1 = router1['router']
            r2 = router2['router']
            r3 = router3['router']
            hd1_id = '00000000-0000-0000-0000-000000000001'
            self._add_router_to_hosting_device(hd1_id, r1['id'])
            self._add_router_to_hosting_device(hd1_id, r2['id'])
            hd2_id = '00000000-0000-0000-0000-000000000002'
            self._add_router_to_hosting_device(hd2_id, r3['id'])
            r_list1 = self._list_routers_hosted_by_hosting_device(hd1_id)
            self.assertEqual(len(r_list1['routers']), 2)
            r1_set = {r1['id'], r2['id']}
            for r in r_list1['routers']:
                self.assertTrue(r1_set)
            r_list2 = self._list_routers_hosted_by_hosting_device(hd2_id)
            self.assertEqual(len(r_list2['routers']), 1)
            self.assertEqual(r_list2['routers'][0]['id'], r3['id'])

    def test_list_routers_by_hosting_device_with_non_existing_hosting_device(
            self):
        with self.router() as router:
            r = router['router']
            hd_id = '00000000-0000-0000-0000-000000000001'
            missing_hd_id = '00000000-0000-0000-0000-000000000099'
            self._add_router_to_hosting_device(hd_id, r['id'])
            r_list = self._list_routers_hosted_by_hosting_device(missing_hd_id)
            self.assertEqual(len(r_list['routers']), 0)

    def test_list_hosting_devices_hosting_router(self):
        with self.router() as router:
            r = router['router']
            hd_id = '00000000-0000-0000-0000-000000000001'
            self._add_router_to_hosting_device(hd_id, r['id'])
            h_list = self._list_hosting_devices_hosting_router(r['id'])
            self.assertEqual(len(h_list['hosting_devices']), 1)
            self.assertEqual(h_list['hosting_devices'][0]['id'], hd_id)

    def test_list_hosting_devices_hosting_unhosted_router(self):
        with self.router() as router:
            r = router['router']
            h_list = self._list_hosting_devices_hosting_router(r['id'])
            self.assertEqual(len(h_list['hosting_devices']), 0)

    def test_list_hosting_devices_hosting_non_existent_router(self):
        with self.router() as router:
            r = router['router']
            r_id_non_exist = r['id'][:-1]
            h_list = self._list_hosting_devices_hosting_router(r_id_non_exist)
            self.assertEqual(len(h_list['hosting_devices']), 0)

    def _test_list_active_sync_routers_on_hosting_devices(self, func):
        with contextlib.nested(self.router(name='router1'),
                               self.router(name='router2'),
                               self.router(name='router3')) as (
                router1, router2, router3):
            r1 = router1['router']
            r2 = router2['router']
            r3 = router3['router']
            hd1_id = '00000000-0000-0000-0000-000000000001'
            self._add_router_to_hosting_device(hd1_id, r1['id'])
            self._add_router_to_hosting_device(hd1_id, r2['id'])
            hd2_id = '00000000-0000-0000-0000-000000000002'
            self._add_router_to_hosting_device(hd2_id, r3['id'])
            # when cfg agent on host_a registers itself, hosting devices with
            # uuid hd1_id and hd2_id will be assigned to that cfg agent
            self._register_cfg_agent_states()
            template_id = '00000000-0000-0000-0000-000000000005'
            with contextlib.nested(self.hosting_device(template_id,
                                                       no_delete=True),
                                   self.router(name='router4'),
                                   self.router(name='router5')) as (
                    h_d3, router4, router5):
                # hd3 should not yet have been assigned to a cfg agent
                hd3 = h_d3['hosting_device']
                r4 = router4['router']
                r5 = router5['router']
                self._add_router_to_hosting_device(hd3['id'], r4['id'])
                self._add_router_to_hosting_device(hd3['id'], r5['id'])
                # when cfg agent on host_b registers itself, hosting
                # device hd3 will be assigned to that cfg agent
                self._register_cfg_agent_states(host_a_active=False,
                                                host_b_active=True)
                agents = self._list(
                    'agents',
                    query_params='agent_type=%s' % c_const.AGENT_TYPE_CFG)
                agent_dict = {agt['host']: agt for agt in agents['agents']}
                if func:
                    func(r1, r2, r3, r4, r5, hd1_id, hd2_id, hd3,
                         template_id, agent_dict)

    def _verify_hosting(self, agent_dict, r_set, host, router_ids=None,
                        hosting_device_ids=None):
        r_l = self.plugin.list_active_sync_routers_on_hosting_devices(
            self.adminContext, host, router_ids, hosting_device_ids)
        self.assertEqual(len(r_l), len(r_set))
        hds = {}
        agent_id = agent_dict[host]['id']
        for r in r_l:
            self.assertEqual(r['id'] in r_set, True)
            router_host = r[HOSTING_DEVICE_ATTR]
            if router_host not in hds:
                hd = self._show('hosting_devices', router_host)
                hds[router_host] = hd['hosting_device']
            self.assertEqual(hds[router_host]['cfg_agent_id'], agent_id)

    def test_list_active_sync_all_routers_on_all_hosting_devices(self):

        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            r_set = {r1['id'], r2['id'], r3['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A)
            r_set = {r4['id'], r5['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_B)

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_some_routers_on_all_hosting_devices(self):

        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            router_ids = [r1['id'], r3['id']]
            r_set = set(router_ids)
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A,
                                 router_ids)

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_all_routers_on_some_hosting_devices(self):
        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            r_set = {r3['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A,
                                 hosting_device_ids=[hd2_id])

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_some_routers_on_some_hosting_devices(self):
        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            router_ids = [r1['id'], r3['id']]
            r_set = {r1['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A,
                                 router_ids, hosting_device_ids=[hd1_id])

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_routers_on_hosting_devices_cfg_agent_admin_down(
            self):

        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            agent_id = agent_dict[device_manager_test_support.L3_CFG_HOST_A][
                'id']
            self._update('agents', agent_id,
                         {'agent': {'admin_state_up': False}})
            r_set = {}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A)
            r_set = {r4['id'], r5['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_B)

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_routers_on_hosting_devices_idle_cfg_agent(
            self):

        def assert_function(r1, r2, r3, r4, r5, hd1_id, hd2_id,
                            hd3, template_id, agent_dict):
            # there should be no hosting devices left that can be assigned
            # to cfg agent on host_c
            self._register_cfg_agent_states(host_a_active=False,
                                            host_b_active=False,
                                            host_c_active=True)
            r_set = {}
            agents = self._list(
                'agents',
                query_params='agent_type=%s' % c_const.AGENT_TYPE_CFG)
            agent_dict = {agt['host']: agt for agt in agents['agents']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_C)
            r_set = {r1['id'], r2['id'], r3['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_A)
            r_set = {r4['id'], r5['id']}
            self._verify_hosting(agent_dict, r_set,
                                 device_manager_test_support.L3_CFG_HOST_B)

        self._test_list_active_sync_routers_on_hosting_devices(assert_function)

    def test_list_active_sync_routers_on_hosting_devices_no_cfg_agent_on_host(
            self):
        self.assertRaises(
            agent.AgentNotFoundByTypeHost,
            self.plugin.list_active_sync_routers_on_hosting_devices,
            self.adminContext, 'bogus_host')

    def test_router_reschedule_from_dead_hosting_device(self):
        with contextlib.nested(
            mock.patch.object(self.plugin, '_backlogged_routers'),
            mock.patch.object(self.plugin, '_refresh_router_backlog',
                              False)) as (m1, m2):
            back_log = set()
            m1.__iter__ = lambda obj: iter(copy.deepcopy(back_log))
            m1.__contains__ = lambda obj, r_id: r_id in back_log
            m1.add.side_effect = lambda r_id: back_log.add(r_id)
            m1.discard.side_effect = lambda r_id: back_log.discard(r_id)
            with contextlib.nested(
                self.router(name='router1'), self.router(name='router2'),
                self.router(name='router3')) as (
                    router1, router2, router3):
                rs_initial = [r['router'] for r in [router1, router2, router3]]
                # all routers initially un-hosted
                for r in rs_initial:
                    self.assertIsNone(r[HOSTING_DEVICE_ATTR])
                hosting_device_id1 = '00000000-0000-0000-0000-000000000001'
                hosting_device_id2 = '00000000-0000-0000-0000-000000000002'
                r_ids = [r['id'] for r in [rs_initial[0], rs_initial[2]]]
                for r_id in r_ids:
                    self._add_router_to_hosting_device(hosting_device_id1,
                                                       r_id)
                self._add_router_to_hosting_device(hosting_device_id2,
                                                   rs_initial[1]['id'])
                rs_after = [self._show('routers', r['id'])['router']
                            for r in rs_initial]
                # r1 and r3 on hosting device 1, r2 on hosting device 2
                for r in [rs_after[0], rs_after[2]]:
                    self.assertEqual(r[HOSTING_DEVICE_ATTR],
                                     hosting_device_id1)
                self.assertEqual(rs_after[1][HOSTING_DEVICE_ATTR],
                                 hosting_device_id2)
                # no routers should be back-logged now
                self.assertEqual(len(back_log), 0)
                hosting_device_1 = self._show(
                    'hosting_devices', hosting_device_id1)['hosting_device']
                affected_resources = {}
                # now report hosting device 1 as dead
                self.plugin.handle_non_responding_hosting_devices(
                    self.adminContext, [hosting_device_1], affected_resources)
                # only routers 1 and 3 should be affected
                affected_rs = affected_resources[hosting_device_id1]['routers']
                self.assertEqual(len(affected_rs), 2)
                # affected routers should be back-logged
                for r_id in r_ids:
                    self.assertIn(r_id, affected_rs)
                    self.assertIn(r_id, back_log)
                rs_final = [self._show('routers', r['id'])['router']
                            for r in rs_initial]
                # routers 1 and 3 should be un-hosted
                for r in [rs_final[0], rs_final[2]]:
                    self.assertIsNone(r[HOSTING_DEVICE_ATTR])
                # router 2 was unaffected and should remain hosted
                self.assertEqual(rs_final[1][HOSTING_DEVICE_ATTR],
                                 hosting_device_id2)


class HostingDeviceRouterL3CfgAgentNotifierTestCase(
        L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase):

    mock_cfg_agent_notifiers = False

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        super(HostingDeviceRouterL3CfgAgentNotifierTestCase, self).setUp(
            core_plugin, l3_plugin, dm_plugin, ext_mgr)
        fake_notifier.reset()

    def test_router_add_to_hosting_device_notification(self):
        l3_notifier = self.plugin.agent_notifiers[c_const.AGENT_TYPE_L3_CFG]
        with contextlib.nested(
            mock.patch.object(l3_notifier.client, 'prepare',
                              return_value=l3_notifier.client),
            mock.patch.object(l3_notifier.client, 'cast'),
                self.router()) as (mock_prepare, mock_cast, router):
            r = router['router']
            # when cfg agent on host_a registers itself, hosting
            # device with uuid hd_id will be assigned to that cfg agent
            self._register_cfg_agent_states()
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            mock_prepare.assert_called_with(
                server=device_manager_test_support.L3_CFG_HOST_A)
            mock_cast.assert_called_with(
                mock.ANY, 'router_added_to_hosting_device',
                routers=[r['id']])
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'hosting_device.router.add'
            self._assert_notify(notifications, expected_event_type)

    def test_router_remove_from_hosting_device_notification(self):
        l3_notifier = self.plugin.agent_notifiers[c_const.AGENT_TYPE_L3_CFG]
        with contextlib.nested(
            mock.patch.object(l3_notifier.client, 'prepare',
                              return_value=l3_notifier.client),
            mock.patch.object(l3_notifier.client, 'cast'),
                self.router()) as (mock_prepare, mock_cast, router):
            r = router['router']
            # when cfg agent on host_a registers itself, hosting
            # device with uuid hd_id will be assigned to that cfg agent
            self._register_cfg_agent_states()
            self._add_router_to_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            self._remove_router_from_hosting_device(
                '00000000-0000-0000-0000-000000000001', r['id'])
            mock_prepare.assert_called_with(
                server=device_manager_test_support.L3_CFG_HOST_A)
            mock_cast.assert_called_with(
                mock.ANY, 'router_removed_from_hosting_device',
                routers=[r['id']])
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'hosting_device.router.remove'
            self._assert_notify(notifications, expected_event_type)

    def test_backlogged_routers_scheduled_routers_updated_notification(self):
        l3_notifier = self.plugin.agent_notifiers[c_const.AGENT_TYPE_L3_CFG]
        with contextlib.nested(
            mock.patch.object(l3_notifier.client, 'prepare',
                              return_value=l3_notifier.client),
            mock.patch.object(l3_notifier.client, 'cast'),
            mock.patch.object(self.plugin, '_backlogged_routers'),
            mock.patch.object(self.plugin, '_refresh_router_backlog',
                              False)) as (
                mock_prepare, mock_cast, mock_b_lg, mock_refresh):
            back_log = set()
            mock_b_lg.__iter__ = lambda obj: iter(copy.deepcopy(back_log))
            mock_b_lg.__contains__ = lambda obj, r_id: r_id in back_log
            mock_b_lg.add.side_effect = lambda r_id: back_log.add(r_id)
            mock_b_lg.discard.side_effect = lambda r_id: back_log.discard(r_id)
            arg_list = (routertype.TYPE_ATTR, )
            # namespace-based router
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000001'}
            self._make_router(self.fmt, _uuid(), 'router1', arg_list=arg_list,
                              **kwargs)
            # router that should be successfully hosted
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000006'}
            r2 = self._make_router(self.fmt, _uuid(), 'router2',
                                   arg_list=arg_list, **kwargs)['router']
            # routertype for which no hosting devices exists
            kwargs = {
                routertype.TYPE_ATTR: '00000000-0000-0000-0000-000000000007'}
            r3 = self._make_router(self.fmt, _uuid(), 'router3',
                                   arg_list=arg_list, **kwargs)['router']
            # routers that should be successfully hosted
            with contextlib.nested(self.router(name='router4'),
                                   self.router(name='router5')) as (
                    router4, router5):
                # when cfg agent on host_a registers itself, hosting
                # devices will be assigned to that cfg agent
                self._register_cfg_agent_states()
                r4 = router4['router']
                r5 = router5['router']
                self.assertEqual(len(back_log), 4)
                for r_id in [r2['id'], r3['id'], r4['id'], r5['id']]:
                    self.assertIn(r_id, back_log)
                self.plugin._process_backlogged_routers()
                mock_prepare.assert_called_with(
                    server=device_manager_test_support.L3_CFG_HOST_A)
                calls = [
                    mock.call(mock.ANY, 'routers_updated', routers=[r2['id']]),
                    mock.call(mock.ANY, 'routers_updated', routers=[r4['id']]),
                    mock.call(mock.ANY, 'routers_updated', routers=[r5['id']])]
                mock_cast.assert_has_calls(calls, any_order=True)
                self.assertEqual(len(back_log), 1)
                self.assertIn(r3['id'], back_log)


class TestHASchedulingL3RouterApplianceExtensionManager(
        TestSchedulingL3RouterApplianceExtensionManager):

    def get_resources(self):
        # add ha attributes to router resource
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            ha.EXTENDED_ATTRIBUTES_2_0['routers'])
        # let our super class do the rest
        return super(TestHASchedulingL3RouterApplianceExtensionManager,
                     self).get_resources()


# A scheduler-enabled routertype capable L3 routing service plugin class
class TestSchedulingHACapableL3RouterServicePlugin(
        ha_db.HA_db_mixin, TestSchedulingCapableL3RouterServicePlugin):

    supported_extension_aliases = [
        "router", routertype.ROUTERTYPE_ALIAS,
        routertypeawarescheduler.ROUTERTYPE_AWARE_SCHEDULER_ALIAS,
        constants.L3_AGENT_SCHEDULER_EXT_ALIAS,
        ha.HA_ALIAS]


class L3RouterHostingDeviceHARandomSchedulerTestCase(
        L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        if l3_plugin is None:
            l3_plugin = HA_L3_PLUGIN_KLASS
        if ext_mgr is None:
            ext_mgr = TestHASchedulingL3RouterApplianceExtensionManager()
        cfg.CONF.set_override('ha_enabled_by_default', True, group='ha')
        cfg.CONF.set_override('default_ha_redundancy_level', 2, group='ha')
        super(L3RouterHostingDeviceHARandomSchedulerTestCase, self).setUp(
            l3_plugin=l3_plugin, ext_mgr=ext_mgr)

    def test_ha_routers_hosted_on_different_hosting_devices(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            with self.router(external_gateway_info={
                    'network_id': s['subnet']['network_id']}) as router:
                r = router['router']
                self.plugin._process_backlogged_routers()
                r_after = self._show('routers', r['id'])['router']
                self.assertIsNotNone(
                    r_after[routerhostingdevice.HOSTING_DEVICE_ATTR])
                hd_ids = {r_after[routerhostingdevice.HOSTING_DEVICE_ATTR]}
                r_rs_after = [self._show('routers', rr['id'])['router']
                              for rr in r[ha.DETAILS][ha.REDUNDANCY_ROUTERS]]
                for rr in r_rs_after:
                    hd_id = rr[routerhostingdevice.HOSTING_DEVICE_ATTR]
                    self.assertIsNotNone(hd_id)
                    self.assertNotIn(hd_id, hd_ids)
                    hd_ids.add(hd_id)