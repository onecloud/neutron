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

import copy

from oslo.config import cfg
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import expression as expr

from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import providernet as pr_net
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.l3.rpc import l3_router_rpc_joint_agent_api

from neutron.openstack.common.notifier import api as notifier_api

from neutron.db import model_base
import sqlalchemy as sa


LOG = logging.getLogger(__name__)


ROUTER_APPLIANCE_OPTS = [
    cfg.IntOpt('backlog_processing_interval',
               default=10,
               help=_('Time in seconds between renewed scheduling attempts of '
                      'non-scheduled routers.')),
]

cfg.CONF.register_opts(ROUTER_APPLIANCE_OPTS, "general")


class RouterCreateInternalError(n_exc.NeutronException):
    message = _("Router could not be created due to internal error.")


class RouterInternalError(n_exc.NeutronException):
    message = _("Internal error during router processing.")


class RouterBindingInfoError(n_exc.NeutronException):
    message = _("Could not get binding information for router %(router_id)s.")

# class L3RouterApplianceDBMixin(extraroute_db.ExtraRoute_dbonly_mixin): # ICEHOUSE_BACKPORT
class L3RouterApplianceDBMixin(extraroute_db.ExtraRoute_db_mixin):
    """Mixin class implementing Neutron's routing service using appliances."""

    # Dictionary of routers for which new scheduling attempts should
    # be made and the refresh setting and heartbeat for that.
    _backlogged_routers = {}
    _refresh_router_backlog = True
    _heartbeat = None

    @property
    def l3_cfg_rpc_notifier(self):
        if not hasattr(self, '_l3_cfg_rpc_notifier'):
            self._l3_cfg_rpc_notifier = (l3_router_rpc_joint_agent_api.
                                         L3RouterJointAgentNotifyAPI(self))
        return self._l3_cfg_rpc_notifier

    @l3_cfg_rpc_notifier.setter
    def l3_cfg_rpc_notifier(self, value):
        self._l3_cfg_rpc_notifier = value

    def create_router(self, context, router):
        with context.session.begin(subtransactions=True):
            if self.mgmt_nw_id() is None:
                raise RouterCreateInternalError()
            router_created = (super(L3RouterApplianceDBMixin, self).
                              create_router(context, router))
            r_hd_b_db = l3_models.RouterHostingDeviceBinding(
                router_id=router_created['id'],
                auto_schedule=True,
                hosting_device_id=None)
            context.session.add(r_hd_b_db)
            # backlog so this new router gets scheduled asynchronously
            self.backlog_router(r_hd_b_db['router'])

        return router_created

    def update_router(self, context, id, router):
        r = router['router']
        # Check if external gateway has changed so we may have to
        # update trunking
        o_r_db = self._get_router(context, id)
        old_ext_gw = (o_r_db.gw_port or {}).get('network_id')
        new_ext_gw = (r.get('external_gateway_info', {}) or {}).get(
            'network_id')
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            if old_ext_gw is not None and old_ext_gw != new_ext_gw:
                o_r = self._make_router_dict(o_r_db, process_extensions=False)
                # no need to schedule now since we're only doing this to
                # tear-down connectivity and there won't be any if not
                # already scheduled.
                self._add_type_and_hosting_device_info(e_context, o_r,
                                                       schedule=False)
                p_drv = self.get_hosting_device_plugging_driver()
                if p_drv is not None:
                    p_drv.teardown_logical_port_connectivity(e_context,
                                                             o_r_db.gw_port)
            router_updated = (
                super(L3RouterApplianceDBMixin, self).update_router(
                    context, id, router))
            routers = [copy.deepcopy(router_updated)]
            self._add_type_and_hosting_device_info(e_context, routers[0])

        self.l3_cfg_rpc_notifier.routers_updated(context, routers)
        return router_updated

    def delete_router(self, context, id):
        router_db = self._get_router(context, id)
        router = self._make_router_dict(router_db)
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
                                                            
            r_hd_binding = self._get_router_binding_info(e_context, id)
            self._add_type_and_hosting_device_info(
                e_context, router, binding_info=r_hd_binding, schedule=False)
            if router_db.gw_port is not None:
                p_drv = self.get_hosting_device_plugging_driver()
                if p_drv is not None:
                    p_drv.teardown_logical_port_connectivity(e_context,
                                                             router_db.gw_port)
                
            # conditionally remove router from backlog just to be sure
            self.remove_router_from_backlog(id)
            if router['hosting_device'] is not None:
                self.unschedule_router_from_hosting_device(context,
                                                           r_hd_binding)

            super(L3RouterApplianceDBMixin, self).delete_router(context, id)
        self.l3_cfg_rpc_notifier.router_deleted(context, router)

    def notify_router_interface_action(
            self, context, router_interface_info, routers, action):
        l3_method = '%s_router_interface' % action
        self.l3_cfg_rpc_notifier.routers_updated(context, routers, l3_method)

        mapping = {'add': 'create', 'remove': 'delete'}
        # notifier = n_rpc.get_notifier('network')
        router_event = 'router.interface.%s' % mapping[action]
        # notifier.info(context, router_event,
        #               {'router_interface': router_interface_info})
      
        # ICEHOUSE_BACKPORT
        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            router_event,
                            notifier_api.CONF.default_notification_level,
                            {'router_interface': router_interface_info})

    def add_router_interface(self, context, router_id, interface_info):
        with context.session.begin(subtransactions=True):
            info = (super(L3RouterApplianceDBMixin, self).
                    add_router_interface(context, router_id, interface_info))
            routers = [self.get_router(context, router_id)]
            self._add_type_and_hosting_device_info(context.elevated(),
                                                   routers[0])
        self.notify_router_interface_action(context, info, routers, 'add')
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        if 'port_id' in (interface_info or {}):
            port_db = self._core_plugin._get_port(
                context, interface_info['port_id'])
        elif 'subnet_id' in (interface_info or {}):
            subnet_db = self._core_plugin._get_subnet(
                context, interface_info['subnet_id'])
            port_db = self._get_router_port_db_on_subnet(
                context, router_id, subnet_db)
        else:
            msg = "Either subnet_id or port_id must be specified"
            raise n_exc.BadRequest(resource='router', msg=msg)
        routers = [self.get_router(context, router_id)]
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            self._add_type_and_hosting_device_info(e_context, routers[0])
            p_drv = self.get_hosting_device_plugging_driver()
            if p_drv is not None:
                p_drv.teardown_logical_port_connectivity(e_context, port_db)
            info = (super(L3RouterApplianceDBMixin, self).
                    remove_router_interface(context, router_id,
                                            interface_info))
        self.notify_router_interface_action(context, info, routers, 'remove')
        return info

    def create_floatingip(
            self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        with context.session.begin(subtransactions=True):
            info = super(L3RouterApplianceDBMixin, self).create_floatingip(
                context, floatingip)
            if info['router_id']:
                routers = [self.get_router(context, info['router_id'])]
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       routers[0])
                self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                         'create_floatingip')
        return info

    def update_floatingip(self, context, id, floatingip):
        orig_fl_ip = super(L3RouterApplianceDBMixin, self).get_floatingip(
            context, id)
        before_router_id = orig_fl_ip['router_id']
        with context.session.begin(subtransactions=True):
            info = super(L3RouterApplianceDBMixin, self).update_floatingip(
                context, id, floatingip)
            router_ids = []
            if before_router_id:
                router_ids.append(before_router_id)
            router_id = info['router_id']
            if router_id and router_id != before_router_id:
                router_ids.append(router_id)
            routers = []
            for router_id in router_ids:
                router = self.get_router(context, router_id)
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       router)
                routers.append(router)
        self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                 'update_floatingip')
        return info

    def delete_floatingip(self, context, id):
        floatingip_db = self._get_floatingip(context, id)
        router_id = floatingip_db['router_id']
        with context.session.begin(subtransactions=True):
            super(L3RouterApplianceDBMixin, self).delete_floatingip(
                context, id)
            if router_id:
                routers = [self.get_router(context, router_id)]
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       routers[0])
                self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                         'delete_floatingip')

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        with context.session.begin(subtransactions=True):
            router_ids = super(L3RouterApplianceDBMixin,
                               self).disassociate_floatingips(context, port_id)
            if router_ids and do_notify:
                routers = []
                for router_id in router_ids:
                    router = self.get_router(context, router_id)
                    self._add_type_and_hosting_device_info(context.elevated(),
                                                           router)
                    routers.append(router)
                self.l3_cfg_rpc_notifier.routers_updated(
                    context, routers, 'disassociate_floatingips')
                # since caller assumes that we handled notifications on its
                # behalf, return nothing
                return
            return router_ids

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _handle_non_responding_hosting_devices(self, context, hosting_devices,
                                               affected_resources):
        """Handle hosting devices determined to be "dead".

        This function is called by the hosting device manager.
        Service plugins are supposed to extend the 'affected_resources'
        dictionary. Hence, we add the id of Neutron routers that are
        hosted in <hosting_devices>.

        param: hosting_devices - list of dead hosting devices
        param: affected_resources - dict with list of affected logical
                                    resources per hosting device:
             {'hd_id1': {'routers': [id1, id2, ...],
                         'fw': [id1, ...],
                         ...},
              'hd_id2': {'routers': [id3, id4, ...],
                         'fw': [id1, ...],
                         ...},
              ...}
        """
        LOG.debug('Processing affected routers in dead hosting devices')
        with context.session.begin(subtransactions=True):
            for hd in hosting_devices:
                hd_bindings = self._get_hosting_device_bindings(context,
                                                                hd['id'])
                router_ids = []
                for binding in hd_bindings:
                    router_ids.append(binding['router_id'])
                    if binding['auto_schedule']:
                        self.backlog_router(binding['router'])
                try:
                    affected_resources[hd['id']].update(
                        {'routers': router_ids})
                except KeyError:
                    affected_resources[hd['id']] = {'routers': router_ids}

    def get_sync_data_ext(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces.

        Adds information about hosting device as well as trunking.
        """
        with context.session.begin(subtransactions=True):
            sync_data = (super(L3RouterApplianceDBMixin, self).
                         get_sync_data(context, router_ids, active))

            for router in sync_data:
                self._add_type_and_hosting_device_info(context, router)
                plg_drv = self.get_hosting_device_plugging_driver()
                if plg_drv and router['hosting_device']:
                    self._add_hosting_port_info(context, router, plg_drv)
        return sync_data

    def schedule_router_on_hosting_device(self, context, r_hd_binding):
        LOG.info(_('Attempting to schedule router %s.'),
                 r_hd_binding['router']['id'])
        result = self._create_csr1kv_vm_hosting_device(context.elevated())
        if result is None:
            # CSR1kv hosting device creation was unsuccessful so backlog
            # it for another scheduling attempt later.
            self.backlog_router(r_hd_binding['router'])
            return False
        with context.session.begin(subtransactions=True):
            router = r_hd_binding['router']
            r_hd_binding.hosting_device = result
            self.remove_router_from_backlog(router['id'])
            LOG.info(_('Successfully scheduled router %(r_id)s to '
                       'hosting device %(d_id)s'),
                     {'r_id': r_hd_binding['router']['id'],
                      'd_id': result['id']})
        return True

    def unschedule_router_from_hosting_device(self, context, r_hd_binding):
        LOG.info(_('Un-schedule router %s.'),
                 r_hd_binding['router']['id'])
        hosting_device = r_hd_binding['hosting_device']
        if r_hd_binding['hosting_device'] is None:
            return False
        self._delete_service_vm_hosting_device(context.elevated(),
                                               hosting_device)

    @lockutils.synchronized('routers', 'neutron-')
    def backlog_router(self, router):
        if ((router or {}).get('id') is None or
                router['id'] in self._backlogged_routers):
            return
        LOG.info(_('Backlogging router %s for renewed scheduling attempt '
                   'later'), router['id'])
        self._backlogged_routers[router['id']] = router

    @lockutils.synchronized('routers', 'neutron-')
    def remove_router_from_backlog(self, id):
        self._backlogged_routers.pop(id, None)
        LOG.info(_('Router %s removed from backlog'), id)

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _process_backlogged_routers(self):
        if self._refresh_router_backlog:
            self._sync_router_backlog()
        if not self._backlogged_routers:
            return
        context = n_context.get_admin_context()
        scheduled_routers = []
        LOG.info(_('Processing router (scheduling) backlog'))
        # try to reschedule
        for r_id, router in self._backlogged_routers.items():
            self._add_type_and_hosting_device_info(context, router)

            if router.get('hosting_device'):
                # scheduling attempt succeeded
                scheduled_routers.append(router)
                self._backlogged_routers.pop(r_id, None)


        # notify cfg agents so the scheduled routers are instantiated
        if scheduled_routers:
            self.l3_cfg_rpc_notifier.routers_updated(context,
                                                     scheduled_routers)

    def _setup_backlog_handling(self):
        self._heartbeat = loopingcall.FixedIntervalLoopingCall(
            self._process_backlogged_routers)
        self._heartbeat.start(
            interval=cfg.CONF.general.backlog_processing_interval)

    def _sync_router_backlog(self):
        LOG.info(_('Synchronizing router (scheduling) backlog'))
        context = n_context.get_admin_context()
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        query = query.options(joinedload('router'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            expr.null())
        for binding in query:
            router = self._make_router_dict(binding.router,
                                            process_extensions=False)
            self._backlogged_routers[binding.router_id] = router
        self._refresh_router_backlog = False

    def _get_router_binding_info(self, context, id, load_hd_info=True):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_hd_info:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                             id)
        try:
            return query.one()
        except exc.NoResultFound:
            # This should not happen
            LOG.error(_('DB inconsistency: No type and hosting info associated'
                        ' with router %s'), id)
            raise RouterBindingInfoError(router_id=id)
        except exc.MultipleResultsFound:
            # This should not happen either
            LOG.error(_('DB inconsistency: Multiple type and hosting info'
                        ' associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)

    def _get_hosting_device_bindings(self, context, id, load_routers=False,
                                     load_hosting_device=False):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_routers:
            query = query.options(joinedload('router'))
        if load_hosting_device:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id == id)
        return query.all()

    def _add_type_and_hosting_device_info(self, context, router,
                                          binding_info=None, schedule=True):
        """Adds type and hosting device information to a router."""

        try:
            if binding_info is None:
                binding_info = self._get_router_binding_info(context,
                                                             router['id'])
        except RouterBindingInfoError:
            LOG.error(_('DB inconsistency: No hosting info associated with '
                        'router %s'), router['id'])
            router['hosting_device'] = None
            return
        router['router_type'] = {
            'id': None,
            'name': 'CSR1kv_router',
            'cfg_agent_driver': (cfg.CONF.hosting_devices
                                 .csr1kv_cfgagent_router_driver)}
        if binding_info.hosting_device is None and schedule:
            # This router has not been scheduled to a hosting device
            # so we try to do it now.
            self.schedule_router_on_hosting_device(context, binding_info)
            context.session.expire(binding_info)
        if binding_info.hosting_device is None:
            router['hosting_device'] = None
        else:
            router['hosting_device'] = self.get_device_info_for_agent(
                binding_info.hosting_device)

    def _get_router_info_for_agent(self, router):
        """Returns information about <router> needed by config agent.

            Convenience function that service plugins can use to populate
            their resources with information about the device hosting their
            logical resource.
        """
        LOG.debug("_get_router_info_for_agent router:%s" % router)
        credentials = {'username': cfg.CONF.hosting_devices.csr1kv_username,
                       'password': cfg.CONF.hosting_devices.csr1kv_password}
        #mgmt_ip = (hosting_device.management_port['fixed_ips'][0]['ip_address']
        #           if hosting_device.management_port else None)
        mgmt_ip = "1.1.1.1"
        return {'id': router['id'],
                'credentials': credentials,
                'management_ip_address': mgmt_ip,
                'protocol_port': 443,
                'created_at': str("AAA"),
                'booting_time': 10,
                'cfg_agent_id': 0}

    def _add_hosting_port_info(self, context, router, plugging_driver):
        """Adds hosting port information to router ports.

        We only populate hosting port info, i.e., reach here, if the
        router has been scheduled to a hosting device. Hence this
        a good place to allocate hosting ports to the router ports.
        """
        # cache of hosting port information: {mac_addr: {'name': port_name}}
        hosting_pdata = {}
                        
        if router['external_gateway_info'] is not None:
            h_info, did_allocation = self._populate_hosting_info_for_port(
                context, router['id'], router['gw_port'],
                router['hosting_device'], hosting_pdata, plugging_driver)
        for itfc in router.get(l3_constants.INTERFACE_KEY, []):
            h_info, did_allocation = self._populate_hosting_info_for_port(
                context, router['id'], itfc, router['hosting_device'],
                hosting_pdata, plugging_driver)

    def _populate_hosting_info_for_port(self, context, router_id, port,
                                        hosting_device, hosting_pdata,
                                        plugging_driver):
        port_db = self._core_plugin._get_port(context, port['id'])
        h_info = port_db.hosting_info
        new_allocation = False
        if h_info is None:
            # The port does not yet have a hosting port so allocate one now
            h_info = self._allocate_hosting_port(
                context, router_id, port_db, hosting_device['id'],
                plugging_driver)
            if h_info is None:
                # This should not happen but just in case ...
                port['hosting_info'] = None
                return None, new_allocation
            else:
                new_allocation = True
        if hosting_pdata.get('mac') is None:
            p_data = self._core_plugin.get_port(
                context, h_info.hosting_port_id, ['mac_address', 'name'])
            hosting_pdata['mac'] = p_data['mac_address']
            hosting_pdata['name'] = p_data['name']
        # Including MAC address of hosting port so L3CfgAgent can easily
        # determine which VM VIF to configure VLAN sub-interface on.
        port['hosting_info'] = {'hosting_port_id': h_info.hosting_port_id,
                                'hosting_mac': hosting_pdata.get('mac'),
                                'hosting_port_name': hosting_pdata.get('name')}
        plugging_driver.extend_hosting_port_info(
            context, port_db, port['hosting_info'])
        return h_info, new_allocation

    def _allocate_hosting_port(self, context, router_id, port_db,
                               hosting_device_id, plugging_driver):
        net_data = self._core_plugin.get_network(
            context, port_db['network_id'], [pr_net.NETWORK_TYPE])
        network_type = net_data.get(pr_net.NETWORK_TYPE)
        alloc = plugging_driver.allocate_hosting_port(
            context, router_id, port_db, network_type, hosting_device_id)
        if alloc is None:
            LOG.error(_('Failed to allocate hosting port for port %s'),
                      port_db['id'])
            return
        with context.session.begin(subtransactions=True):
            h_info = l3_models.HostedHostingPortBinding(
                logical_resource_id=router_id,
                logical_port_id=port_db['id'],
                network_type=network_type,
                hosting_port_id=alloc['allocated_port_id'],
                segmentation_id=alloc['allocated_vlan'])
            context.session.add(h_info)
            context.session.expire(port_db)
        # allocation succeeded so establish connectivity for logical port
        context.session.expire(h_info)
        plugging_driver.setup_logical_port_connectivity(context, port_db)
        return h_info

    def _get_router_port_db_on_subnet(self, context, router_id, subnet):
        try:
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet['id']:
                    return p
        except exc.NoResultFound:
            return

    def list_active_sync_routers_on_hosting_devices(self, context, host,
                                                    router_ids=None,
                                                    hosting_device_ids=None):
        agent = self._get_agent_by_type_and_host(
            context, c_const.AGENT_TYPE_CFG, host)
        if not agent.admin_state_up:
            return []
            
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(l3_models.HostingDevice)
        query = query.filter(l3_models.HostingDevice.cfg_agent_id == agent.id)
        if router_ids:
            if len(router_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id ==
                    router_ids[0])
            else:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id.in_(
                        router_ids))
        if hosting_device_ids:
            if len(hosting_device_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id ==
                    hosting_device_ids[0])
            elif len(hosting_device_ids) > 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id.in_(
                        hosting_device_ids))
        router_ids = [item[0] for item in query]
        if router_ids:
            return self.get_sync_data_ext(context, router_ids=router_ids,
                                          active=True)
        else:
            return []


class CiscoPhysicalRouter(model_base.BASEV2, models_v2.HasId):
    """Represents a physical cisco router."""

    __tablename__ = 'cisco_phy_routers'

    name = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16))
    # other columns TBD


class CiscoPhyRouterPortBinding(model_base.BASEV2):
    """ HSRP interface mappings to physical ASRs """

    __tablename__ = 'cisco_phy_router_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("subnets.id", ondelete='CASCADE'))

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'))

    phy_router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("cisco_phy_routers.id", ondelete='CASCADE'))

from neutron.api.v2 import attributes
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants

PHYSICAL_GLOBAL_ROUTER_ID = "PHYSICAL_GLOBAL_ROUTER_ID"

class PhysicalL3RouterApplianceDBMixin(L3RouterApplianceDBMixin):


    @property
    def l3_cfg_rpc_notifier(self):
        if not hasattr(self, '_l3_cfg_rpc_notifier'):
            self._l3_cfg_rpc_notifier = (l3_router_rpc_joint_agent_api.
                                         PhysicalL3RouterJointAgentNotifyAPI(self))
        return self._l3_cfg_rpc_notifier

    def _phy_l3_mixin_init(self):
        from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (asr1k_routing_driver as asr1k_driver)
        self._db_synced = False
        self.asr_cfg_info = asr1k_driver.ASR1kConfigInfo()

    def sync_asr_list_with_db(self, context, asr_list):

        if self._db_synced is True:
            return
        
        db_names = []
        cfg_names = []
        missing_db_asr_list = []
        #asr_list = self.get_asr_list()

        phy_router_qry = context.session.query(CiscoPhysicalRouter).all()

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
                    new_db_asr = CiscoPhysicalRouter(name=asr['name'])
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

            LOG.info("added new port %s" % (asr_port))
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
        if dev_owner == l3_constants.DEVICE_OWNER_ROUTER_HA_GW:
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
        info = super(PhysicalL3RouterApplianceDBMixin, self).add_router_interface(context,
                                                                                  router_id,
                                                                                  interface_info)

        
        LOG.info("finished parent add_router_interface, info:%s" % (info))

        # If no exception has been raised, we're good to go            
        subnet_id = info['subnet_id']
        subnet = self._core_plugin._get_subnet(context, subnet_id)

        self._create_hsrp_interfaces(context, router_id, subnet, 
                                     l3_constants.DEVICE_OWNER_ROUTER_HA_INTF)
        
        return info



    def remove_router_interface(self, context, router_id, interface_info):
        info = super(PhysicalL3RouterApplianceDBMixin, self).remove_router_interface(context,
                                                                                     router_id,
                                                                                     interface_info)

        LOG.info("finished parent remove_router_interface, info:%s" % (info))

        # If no exception has been raised, we're good to go            
        subnet_id = info['subnet_id']
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        
        self._delete_hsrp_interfaces(context, router_id, subnet,
                                     l3_constants.DEVICE_OWNER_ROUTER_HA_INTF)

        return info


    def _bind_hsrp_interfaces_to_router(self, context, router_id,  port_list):
         # go ahead and map these interfaces to physical ASRs
        self.sync_asr_list_with_db(context, self.asr_cfg_info.get_asr_list())
        
        phy_router_qry = context.session.query(CiscoPhysicalRouter).all()

        for db_asr, port in zip(phy_router_qry, port_list):            
            port_binding = CiscoPhyRouterPortBinding(port_id=port['id'],
                                                     subnet_id=port['fixed_ips'][0]['subnet_id'],
                                                     router_id=router_id,
                                                     phy_router_id=db_asr.id)

            with context.session.begin(subtransactions=True):
                context.session.add(port_binding)

    '''
    How many routers have a port associated with a particular external network?
    '''
    def _count_ha_routers_on_network(self, context, network_id):
        rport_qry = context.session.query(models_v2.Port)
        asr_ports = rport_qry.filter_by(device_owner=l3_constants.DEVICE_OWNER_ROUTER_GW,
                                        network_id=network_id)

        num_ports = asr_ports.count()
        LOG.info("num routers on network: %s, %s" % (network_id, num_ports))
        for port in asr_ports:
            LOG.info("port: %s" % (port))
        return num_ports
    
    def _send_physical_global_router_updated_notification(self, context):
        phy_router = self.get_router(context, PHYSICAL_GLOBAL_ROUTER_ID)
        if phy_router:
            self.l3_cfg_rpc_notifier.routers_updated(context,
                                                     [phy_router])
    '''
    Create a router construct used to hold "global" external network 
    HSRP interfaces of type DEVICE_OWNER_ROUTER_HA_GW
    '''
    def _create_physical_global_router(self, context):

        context = context.elevated()
        
        global_router_qry = context.session.query(l3_db.Router)
        global_router_qry = global_router_qry.filter_by(id=PHYSICAL_GLOBAL_ROUTER_ID)
        if global_router_qry.count() > 0:
            return
        
        with context.session.begin(subtransactions=True):
            router_db = l3_db.Router(id=PHYSICAL_GLOBAL_ROUTER_ID,
                                     tenant_id='',
                                     name=PHYSICAL_GLOBAL_ROUTER_ID,
                                     admin_state_up=True,
                                     status="ACTIVE")
            context.session.add(router_db)
            self._send_physical_global_router_updated_notification(context)

        return
        #return self._make_router_dict(router_db, process_extensions=False)

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
                     #'device_id': network_id,
                     'device_id': PHYSICAL_GLOBAL_ROUTER_ID,
                     'device_owner': l3_constants.DEVICE_OWNER_ROUTER_HA_GW,
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

        self._create_physical_global_router(context)

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
            if self._count_ha_routers_on_network(context, gw_port['network_id']) == 0:
                self._delete_hsrp_interfaces(context.elevated(), None, subnet,
                                             l3_constants.DEVICE_OWNER_ROUTER_HA_GW)
                self._send_physical_global_router_updated_notification(context)


        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._core_plugin._get_subnets_by_network(context,
                                                                network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router_id,
                                                  network_id, subnet['id'],
                                                  subnet['cidr'])

            # Only create HA ports if we are the first to create VLAN subinterface for this ext network
            needs_hsrp_create = False
            if self._count_ha_routers_on_network(context, network_id) == 0:
                needs_hsrp_create = True

            self._create_router_gw_port(context, router, network_id)
            
            if needs_hsrp_create is True:
                self._create_router_gw_hsrp_interfaces(context, router, network_id, router.gw_port)
                self._send_physical_global_router_updated_notification(context)


    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context.elevated(),
                                              filters={'router_id': [id]})
            if fips:
                raise l3.RouterInUse(router_id=id)

            device_filter = {'device_id': [id],
                             'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_INTF]}
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
                             'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_GW]}
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
                                     'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_HA_GW]}
                    gw_ha_ports = self._core_plugin.get_ports(context.elevated(),
                                                              filters=device_filter)
                    for gw_ha_port in gw_ha_ports:
                        self._core_plugin._delete_port(context.elevated(),
                                                       gw_ha_port['id'])
                   
                    self._send_physical_global_router_updated_notification(context)

            self.l3_cfg_rpc_notifier.router_deleted(context, router)


    
    def create_router(self, context, router):
        with context.session.begin(subtransactions=True):
            router_created = (super(L3RouterApplianceDBMixin, self).
                              create_router(context, router))
            self.backlog_router(router_created)  # backlog or start immediatey?
        return router_created


    def update_router(self, context, id, router):
        r = router['router']
        # Check if external gateway has changed so we may have to
        # update trunking
        o_r_db = self._get_router(context, id)
        old_ext_gw = (o_r_db.gw_port or {}).get('network_id')
        new_ext_gw = (r.get('external_gateway_info', {}) or {}).get(
            'network_id')
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            if old_ext_gw is not None and old_ext_gw != new_ext_gw:
                o_r = self._make_router_dict(o_r_db, process_extensions=False)
                # no need to schedule now since we're only doing this to
                # tear-down connectivity and there won't be any if not
                # already scheduled.
                self._add_type_and_hosting_device_info(e_context, o_r,
                                                       schedule=False)
            router_updated = (
                super(L3RouterApplianceDBMixin, self).update_router(
                    context, id, router))
            routers = [copy.deepcopy(router_updated)]
            self._add_type_and_hosting_device_info(e_context, routers[0])

        self.l3_cfg_rpc_notifier.routers_updated(context, routers)
        return router_updated

    def _process_sync_data(self, routers, interfaces, floating_ips, ha_gw_interfaces= []):
        routers_dict = {}
        for router in routers:
            routers_dict[router['id']] = router
        for floating_ip in floating_ips:
            router = routers_dict.get(floating_ip['router_id'])
            if router:
                router_floatingips = router.get(l3_constants.FLOATINGIP_KEY,
                                                [])
                router_floatingips.append(floating_ip)
                router[l3_constants.FLOATINGIP_KEY] = router_floatingips
        for interface in interfaces:
            router = routers_dict.get(interface['device_id'])
            if router:
                router_interfaces = router.get(l3_constants.INTERFACE_KEY, [])
                router_interfaces.append(interface)
                router[l3_constants.INTERFACE_KEY] = router_interfaces

        for interface in ha_gw_interfaces:
            router = routers_dict.get(interface['device_id'])
            if router:
                router_interfaces = router.get(l3_constants.HA_GW_KEY, [])
                router_interfaces.append(interface)
                router[l3_constants.HA_GW_KEY] = router_interfaces

        return routers_dict.values()


    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = self._get_sync_routers(context,
                                             router_ids=router_ids,
                                             active=active)
            router_ids = [router['id'] for router in routers]
            floating_ips = self._get_sync_floating_ips(context, router_ids)
            interfaces = self.get_sync_interfaces(context, router_ids)

            ha_interfaces = self.get_sync_interfaces(context, router_ids,
                                                     l3_constants.DEVICE_OWNER_ROUTER_HA_INTF)
            ha_gw_interfaces = self.get_sync_interfaces(context, router_ids,
                                                        l3_constants.DEVICE_OWNER_ROUTER_HA_GW)

            # Retrieve physical router port bindings
            all_ha_interfaces = ha_interfaces + ha_gw_interfaces
            for ha_intf in all_ha_interfaces:
                port_id = ha_intf['id']
                phy_port_qry = context.session.query(CiscoPhyRouterPortBinding, CiscoPhysicalRouter)
                phy_port_qry = phy_port_qry.filter(CiscoPhyRouterPortBinding.port_id == port_id)
                port_binding_db, phy_router_db = phy_port_qry.filter(CiscoPhyRouterPortBinding.phy_router_id == CiscoPhysicalRouter.id).first()

                ha_intf['port_binding_db'] = port_binding_db
                ha_intf['phy_router_db'] = phy_router_db                

            interfaces += ha_interfaces

        return self._process_sync_data(routers, interfaces, floating_ips, ha_gw_interfaces)


    def get_sync_data_ext(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces.

        Adds information about hosting device as well as trunking.
        """
        with context.session.begin(subtransactions=True):
            sync_data = self.get_sync_data(context, router_ids, active)

            for router in sync_data:
                self._add_type_and_hosting_device_info(context, router)
                self._add_hosting_port_info(context, router, None)

            return sync_data

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _process_backlogged_routers(self):
        if self._refresh_router_backlog:
            self._sync_router_backlog()
        if not self._backlogged_routers:
            return
        context = n_context.get_admin_context()
        scheduled_routers = []
        LOG.info(_('Processing router (scheduling) backlog'))
        # try to reschedule
        for r_id, router in self._backlogged_routers.items():
            self._add_type_and_hosting_device_info(context, router)

            scheduled_routers.append(router)
            self._backlogged_routers.pop(r_id, None)

        # notify cfg agents so the scheduled routers are instantiated
        if scheduled_routers:
            self.l3_cfg_rpc_notifier.routers_updated(context,
                                                     scheduled_routers)


    def _add_type_and_hosting_device_info(self, context, router,
                                          binding_info=None, schedule=True):
        """Adds type and hosting device information to a router."""
        LOG.debug("_add_type_and_hosting_device_info router:%s" % router)
        router['router_type'] = {'id': None,
                                 'name': 'CSR1kv_router',
                                 'cfg_agent_driver': (cfg.CONF.hosting_devices
                                                      .csr1kv_cfgagent_router_driver)}
        router['hosting_device'] = self._get_router_info_for_agent(router)
        return

    def _add_hosting_port_info(self, context, router, plugging_driver):
        """Adds hosting port information to router ports.

        We only populate hosting port info, i.e., reach here, if the
        router has been scheduled to a hosting device. Hence this
        a good place to allocate hosting ports to the router ports.
        """
        # cache of hosting port information: {mac_addr: {'name': port_name}}
        hosting_pdata = {}
                        
        if router['external_gateway_info'] is not None:
            self._get_hosting_info_for_port_no_vm(context, 
                                                  router['id'], router['gw_port'],
                                                  hosting_pdata)

        for itfc in router.get(l3_constants.INTERFACE_KEY, []):
            self._get_hosting_info_for_port_no_vm(context,
                                                  router['id'], itfc, 
                                                  hosting_pdata)
        
        for itfc in router.get(l3_constants.HA_GW_KEY, []):
            self._get_hosting_info_for_port_no_vm(context,
                                                  router['id'], itfc, 
                                                  hosting_pdata)

    def _get_hosting_info_for_port_no_vm(self, context, router_id, port, hosting_pdata):
        port_db = self._core_plugin._get_port(context, port['id'])
        tags = self._core_plugin.get_networks(context,
                                              {'id': [port_db['network_id']]},
                                              [pr_net.SEGMENTATION_ID])
        allocated_vlan = (None if tags == []
                          else tags[0].get(pr_net.SEGMENTATION_ID))

        if hosting_pdata.get('mac') is None:
            hosting_pdata['mac'] = "mac_placeholder"
            hosting_pdata['name'] = "intf_name_placeholder"

        port['hosting_info'] = {'hosting_port_id': 0,
                                'segmentation_id': allocated_vlan,
                                'hosting_mac': hosting_pdata['mac'],
                                'hosting_port_name': hosting_pdata['name']}

    def list_active_sync_routers_on_hosting_devices(self, context, host,
                                                    router_ids=None,
                                                    hosting_device_ids=None):
        agent = self._get_agent_by_type_and_host(
            context, c_const.AGENT_TYPE_CFG, host)
        if not agent.admin_state_up:
            return []
            
        if router_ids is None:
            router_ids = []
            routers = self.get_routers(context)
            for router in routers:
                router_ids.append(router['id'])

        LOG.info("active sync router_ids: %s" % (router_ids))

        return self.get_sync_data_ext(context, router_ids=router_ids,
                                      active=True)
