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
#
# @author: Bob Melander, Cisco Systems, Inc.

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
# from neutron.db import common_db_mixin  # ICEHOUSE_BACKPORT
from neutron.db import db_base_plugin_v2
from neutron import manager
from neutron.plugins.cisco.db.l3 import device_handling_db
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.l3.rpc import (l3_router_cfgagent_rpc_cb as
                                          l3_router_rpc)
from neutron.plugins.cisco.l3.rpc import devices_cfgagent_rpc_cb as devices_rpc
from neutron.plugins.common import constants

from neutron.openstack.common import rpc as o_rpc  # ICEHOUSE_BACKPORT
from neutron.db import l3_rpc_base 
from neutron.db import l3_db

from neutron.common import exceptions as n_exc
from neutron.openstack.common.notifier import api as notifier_api
from neutron.api.v2 import attributes


# class CiscoRouterPluginRpcCallbacks(n_rpc.RpcCallback, # ICEHOUSE_BACKPORT
class CiscoRouterPluginRpcCallbacks(l3_router_rpc.L3RouterCfgRpcCallbackMixin,
                                    l3_rpc_base.L3RpcCallbackMixin,
                                    devices_rpc.DeviceCfgRpcCallbackMixin):
    RPC_API_VERSION = '1.1'

    def __init__(self, l3plugin):
        super(CiscoRouterPluginRpcCallbacks, self).__init__()
        self._l3plugin = l3plugin

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])

# class CiscoRouterPlugin(common_db_mixin.CommonDbMixin, # ICEHOUSE_BACKPORT
class CiscoRouterPlugin(db_base_plugin_v2.CommonDbMixin,
                        agents_db.AgentDbMixin,
                        l3_router_appliance_db.L3RouterApplianceDBMixin,
                        device_handling_db.DeviceHandlingMixin):

    """Implementation of Cisco L3 Router Service Plugin for Neutron.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB functionality is implemented in class
    l3_router_appliance_db.L3RouterApplianceDBMixin.
    """
    supported_extension_aliases = ["router", "extraroute"]

    def __init__(self):
        self.setup_rpc()
        # for backlogging of non-scheduled routers
        self._setup_backlog_handling()
        self._setup_device_handling()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        # self.conn = n_rpc.create_connection(new=True)  # ICEHOUSE_BACKPORT
        self.conn = o_rpc.create_connection(new=True)
        self.callbacks = CiscoRouterPluginRpcCallbacks(self)  # ICEHOUSE_BACKPORT
        self.dispatcher = self.callbacks.create_rpc_dispatcher() # ICEHOUSE_BACKPORT
        self.endpoints = [CiscoRouterPluginRpcCallbacks(self)]
        # self.conn.create_consumer(self.topic, self.endpoints, # ICEHOUSE_BACKPORT
        #                           fanout=False)
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in threads
        # self.conn.consume_in_threads()  # ICEHOUSE_BACKPORT
        self.conn.consume_in_thread()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return ("Cisco Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin


class PhysicalCiscoRouterPlugin(db_base_plugin_v2.CommonDbMixin,
                                agents_db.AgentDbMixin,
                                l3_router_appliance_db.PhysicalL3RouterApplianceDBMixin,
                                device_handling_db.DeviceHandlingMixin,
                                l3_db.L3_NAT_db_mixin):

    """Implementation of Cisco L3 Router Service Plugin for Neutron.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB functionality is implemented in class
    l3_router_appliance_db.L3RouterApplianceDBMixin.
    """
    supported_extension_aliases = ["router", "extraroute"]

    def __init__(self):
        self.setup_rpc()
        # for backlogging of non-scheduled routers
        self._setup_backlog_handling()
        self._setup_device_handling()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        # self.conn = n_rpc.create_connection(new=True)  # ICEHOUSE_BACKPORT
        self.conn = o_rpc.create_connection(new=True)
        self.callbacks = CiscoRouterPluginRpcCallbacks(self)  # ICEHOUSE_BACKPORT
        self.dispatcher = self.callbacks.create_rpc_dispatcher() # ICEHOUSE_BACKPORT
        self.endpoints = [CiscoRouterPluginRpcCallbacks(self)]
        # self.conn.create_consumer(self.topic, self.endpoints, # ICEHOUSE_BACKPORT
        #                           fanout=False)
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in threads
        # self.conn.consume_in_threads()  # ICEHOUSE_BACKPORT
        self.conn.consume_in_thread()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return ("Cisco Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def add_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise n_exc.BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            # make sure port update is committed
            with context.session.begin(subtransactions=True):
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise n_exc.BadRequest(resource='router', msg=msg)

                port = self._core_plugin._get_port(context,
                                                   interface_info['port_id'])
                if port['device_id']:
                    raise n_exc.PortInUse(net_id=port['network_id'],
                                          port_id=port['id'],
                                          device_id=port['device_id'])
                fixed_ips = [ip for ip in port['fixed_ips']]
                if len(fixed_ips) != 1:
                    msg = _('Router port must have exactly one fixed IP')
                    raise n_exc.BadRequest(resource='router', msg=msg)
                subnet_id = fixed_ips[0]['subnet_id']
                subnet = self._core_plugin._get_subnet(context, subnet_id)
                self._check_for_dup_router_subnet(context, router_id,
                                                  port['network_id'],
                                                  subnet['id'],
                                                  subnet['cidr'])
                port.update({'device_id': router_id,
                             'device_owner': l3_db.DEVICE_OWNER_ROUTER_INTF})
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._core_plugin._get_subnet(context, subnet_id)
            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = _('Subnet for router interface must have a gateway IP')
                raise n_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router_id,
                                              subnet['network_id'],
                                              subnet_id,
                                              subnet['cidr'])
            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}
            port = self._core_plugin.create_port(context, {
                'port':
                {'tenant_id': subnet['tenant_id'],
                 'network_id': subnet['network_id'],
                 'fixed_ips': [fixed_ip],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'admin_state_up': True,
                 'device_id': router_id,
                 'device_owner': l3_db.DEVICE_OWNER_ROUTER_INTF,
                 'name': ''}})

        self.l3_rpc_notifier.routers_updated(
            context, [router_id], 'add_router_interface')
        info = {'id': router_id,
                'tenant_id': subnet['tenant_id'],
                'port_id': port['id'],
                'subnet_id': port['fixed_ips'][0]['subnet_id']}
        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.create',
                            notifier_api.CONF.default_notification_level,
                            {'router_interface': info})
        return info

    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin
