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

from neutron.openstack.common.notifier import api as notifier_api
from neutron.api.v2 import attributes
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.common import exceptions as n_exc
from neutron.extensions import l3
from neutron.common import constants as common_constants

from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (asr1k_routing_driver as asr1k_driver)

LOG = logging.getLogger(__name__)


DEVICE_OWNER_ROUTER_HA_INTF = "network:router_ha_interface"
DEVICE_OWNER_ROUTER_HA_GW = "network:router_ha_gateway"


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

        self.asr_cfg_info = asr1k_driver.ASR1kConfigInfo()
        self._db_synced = False

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

    def sync_asr_list_with_db(self, context, asr_list):

        if self._db_synced is True:
            return
        
        db_names = []
        cfg_names = []
        missing_db_asr_list = []
        #asr_list = self.get_asr_list()

        phy_router_qry = context.session.query(l3_router_appliance_db.CiscoPhysicalRouter).all()

        # Build list of names that exist in cfg
        for asr in asr_list:
            cfg_names.append(asr['name'])

        # Build list of names that exist in DB
        # Build list of db objects that do not have names in cfg
        for db_asr in phy_router_qry:
            db_names.append(db_asr.name)
            if db_asr.name not in cfg_names:
                missing_db_asr_list.append(db_asr)

        # Update DB
        with context.session.begin(subtransactions=True):

            # Add ASRs from cfg with names not in db 
            for asr in asr_list:
                if asr['name'] not in db_names:
                    new_db_asr = l3_router_appliance_db.CiscoPhysicalRouter(name=asr['name'])
                    context.session.add(new_db_asr)

            # Delete missing ASRs from db
            for missing_asr in missing_db_asr_list:
                # context.session.delete(missing_asr)
                missing_asr.delete()
        
        self._db_synced = True

    def _create_hsrp_interfaces(self, context, router_id, subnet, dev_owner):
        # Create HSRP standby interfaces
        port_list = []
        num_asr = len(self.asr_cfg_info.get_asr_list())
        for asr_idx in range(0, num_asr):
            asr_port = self._core_plugin.create_port(context, {
                'port':
                {'tenant_id': subnet['tenant_id'],
                 'network_id': subnet['network_id'],
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'admin_state_up': True,
                 'device_id': router_id,
                 'device_owner': dev_owner,
                 'name': ''}})

            LOG.error("ZXCVWSAD added new port %s" % (asr_port))
            port_list.append(asr_port)
        
        for port in port_list:
            self.l3_rpc_notifier.routers_updated(
                context, [router_id], 'add_router_interface')
            ha_info = {'id': router_id,
                       'tenant_id': subnet['tenant_id'],
                       'port_id': port['id'],
                       'subnet_id': port['fixed_ips'][0]['subnet_id']}
            notifier_api.notify(context,
                                notifier_api.publisher_id('network'),
                                'router.interface.create',
                                notifier_api.CONF.default_notification_level,
                                {'router_interface': ha_info})

        self._bind_hsrp_interfaces_to_router(context, router_id,  port_list)


    def _delete_hsrp_interfaces(self, context, router_id, subnet, dev_owner):
        # Delete HSRP standby interfaces
        port_list = []
        rport_qry = context.session.query(models_v2.Port)
        if router_id is None:
            asr_ports = rport_qry.filter_by(device_owner=dev_owner,
                                            network_id=subnet['network_id'])
        else:
             asr_ports = rport_qry.filter_by(device_id=router_id,
                                             device_owner=dev_owner,
                                             network_id=subnet['network_id'])


        for asr_port in asr_ports:
            port_list.append(asr_port)
            self._core_plugin.delete_port(context, asr_port['id'],
                                          l3_port_check=False)
            LOG.error("ZXCVWSAD deleted port %s" % (asr_port))

        # don't notify if gw hsrp interfaces are deleted
        if dev_owner == DEVICE_OWNER_ROUTER_HA_GW:
            return
            
        for port in port_list:
            self.l3_rpc_notifier.routers_updated(
                context, [router_id], 'remove_router_interface')
            ha_info = {'id': router_id,
                       'tenant_id': subnet['tenant_id'],
                       'port_id': port['id'],
                       'subnet_id': subnet['id']}
            notifier_api.notify(context,
                                notifier_api.publisher_id('network'),
                                'router.interface.delete',
                                notifier_api.CONF.default_notification_level,
                                {'router_interface': ha_info})
        

    def add_router_interface(self, context, router_id, interface_info):
        info = super(PhysicalCiscoRouterPlugin, self).add_router_interface(context,
                                                                           router_id,
                                                                           interface_info)

        
        LOG.error("ZXCVWSAD finished parent add_router_interface, info:%s" % (info))

        # If no exception has been raised, we're good to go            
        subnet_id = info['subnet_id']
        subnet = self._core_plugin._get_subnet(context, subnet_id)

        self._create_hsrp_interfaces(context, router_id, subnet, DEVICE_OWNER_ROUTER_HA_INTF)
        
        return info



    def remove_router_interface(self, context, router_id, interface_info):
        info = super(PhysicalCiscoRouterPlugin, self).remove_router_interface(context,
                                                                              router_id,
                                                                              interface_info)

        LOG.error("ZXCVWSAD finished parent remove_router_interface, info:%s" % (info))

        # If no exception has been raised, we're good to go            
        subnet_id = info['subnet_id']
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        
        self._delete_hsrp_interfaces(context, router_id, subnet, DEVICE_OWNER_ROUTER_HA_INTF)

        return info


    def _bind_hsrp_interfaces_to_router(self, context, router_id,  port_list):
         # go ahead and map these interfaces to physical ASRs
        self.sync_asr_list_with_db(context, self.asr_cfg_info.get_asr_list())
        
        phy_router_qry = context.session.query(l3_router_appliance_db.CiscoPhysicalRouter).all()

        for db_asr, port in zip(phy_router_qry, port_list):            
            port_binding = l3_router_appliance_db.CiscoPhyRouterPortBinding(port_id=port['id'],
                                                                            subnet_id=port['fixed_ips'][0]['subnet_id'],
                                                                            router_id=router_id,
                                                                            phy_router_id=db_asr.id)

            with context.session.begin(subtransactions=True):
                context.session.add(port_binding)


    def _count_ha_routers_on_network(self, context, network_id):
        rport_qry = context.session.query(models_v2.Port)
        asr_ports = rport_qry.filter_by(device_owner=DEVICE_OWNER_ROUTER_HA_GW,
                                        network_id=network_id)

        num_ports = len(asr_ports)
        return num_ports
        

    ''' 
    Create HSRP standby interfaces for external network.
    
    As these are 'global' resources, shared across tenants and routers,
    they will not have a device_id associated.
    
    They will only be created when an external network is assigned to a router 
    for the first time.

    They will be deleted when an external network is no longer assigned to any
    virtual router.
    '''    
    def _create_router_gw_hsrp_interfaces(self, context, router, network_id, main_gw_port):
        # Port has no 'tenant-id', as it is hidden from user

        port_list = [main_gw_port]
        num_asr = len(self.asr_cfg_info.get_asr_list())
        for asr_idx in range(0, num_asr):

            gw_port = self._core_plugin.create_port(context.elevated(), {
            'port': {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                     #'device_id': router['id'],
                     'device_owner': DEVICE_OWNER_ROUTER_HA_GW,
                     'admin_state_up': True,
                     'name': ''}})

            port_list.append(gw_port)
            
            if not gw_port['fixed_ips']:
                for deleted_port in port_list:
                    self._core_plugin.delete_port(context.elevated(), deleted_port['id'],
                                                  l3_port_check=False)
                    msg = (_('Not enough IPs available for external network %s') %
                           network_id)
                
                raise n_exc.BadRequest(resource='router', msg=msg)

        self._bind_hsrp_interfaces_to_router(context, router['id'],  port_list[1:])

    
    def _update_router_gw_info(self, context, router_id, info, router=None):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        router = router or self._get_router(context, router_id)
        gw_port = router.gw_port
        # network_id attribute is required by API, so it must be present
        network_id = info['network_id'] if info else None
        if network_id:
            network_db = self._core_plugin._get_network(context, network_id)
            if not network_db.external:
                msg = _("Network %s is not a valid external "
                        "network") % network_id
                raise n_exc.BadRequest(resource='router', msg=msg)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            fip_count = self.get_floatingips_count(context.elevated(),
                                                   {'router_id': [router_id]})
            if fip_count:
                raise l3.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router_id, net_id=gw_port['network_id'])
            with context.session.begin(subtransactions=True):
                router.gw_port = None
                context.session.add(router)
            
            subnet_id = gw_port['fixed_ips'][0]['subnet_id']
            subnet = self._core_plugin._get_subnet(context.elevated(), subnet_id)

            self._core_plugin.delete_port(context.elevated(),
                                          gw_port['id'],
                                          l3_port_check=False)

            # No external gateway assignments left, clear the HSRP interfaces
            if self._count_ha_routers_on_network(context, network_id) == 0:
                self._delete_hsrp_interfaces(context.elevated(), None, subnet,
                                             common_constants.DEVICE_OWNER_ROUTER_HA_GW)


        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._core_plugin._get_subnets_by_network(context,
                                                                network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router_id,
                                                  network_id, subnet['id'],
                                                  subnet['cidr'])

            # Only create HA ports if we are the first to create VLAN subinterface for this ext network
            if self._count_ha_routers_on_network(context, network_id) == 0:
                needs_hsrp_create = True

            self._create_router_gw_port(context, router, network_id)
            
            if needs_hsrp_create is True:
                self._create_router_gw_hsrp_interfaces(context, router, network_id, router.gw_port)


    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context.elevated(),
                                              filters={'router_id': [id]})
            if fips:
                raise l3.RouterInUse(router_id=id)

            device_filter = {'device_id': [id],
                             'device_owner': [common_constants.DEVICE_OWNER_ROUTER_INTF]}
            ports = self._core_plugin.get_ports_count(context.elevated(),
                                                      filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=id)

            #TODO(nati) Refactor here when we have router insertion model
            vpnservice = manager.NeutronManager.get_service_plugins().get(
                constants.VPN)
            if vpnservice:
                vpnservice.check_router_in_use(context, id)

            context.session.delete(router)

            # Delete the gw port after the router has been removed to
            # avoid a constraint violation.
            device_filter = {'device_id': [id],
                             'device_owner': [common_constants.DEVICE_OWNER_ROUTER_GW]}
            ports = self._core_plugin.get_ports(context.elevated(),
                                                filters=device_filter)
            for port in ports:
                self._core_plugin._delete_port(context.elevated(),
                                               port['id'])

            # if this router had no gw port, we are done
            if len(ports) > 0:

                # If this router was the last one with a gw port on this network
                # delete the HSRP gw ports
                network_id = ports[0]['network_id']
                if self._count_ha_routers_on_network(context, network_id) == 0:                
                    device_filter = {'network_id': [id],
                                     'device_owner': [common_constants.DEVICE_OWNER_ROUTER_HA_GW]}
                    gw_ha_ports = self._core_plugin.get_ports(context.elevated(),
                                                              filters=device_filter)
                    for gw_ha_port in gw_ha_ports:
                        self._core_plugin._delete_port(context.elevated(),
                                                       gw_ha_port['id'])

        self.l3_rpc_notifier.router_deleted(context, id)




    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin
