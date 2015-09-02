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
# Cisco Systems, Inc.

import ciscoconfparse
import netaddr
import re
import xml.etree.ElementTree as ET

from neutron.common import constants
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import \
    asr1k_snippets as asr_snippets

LOG = logging.getLogger(__name__)

TENANT_HSRP_GRP_RANGE = 1
TENANT_HSRP_GRP_OFFSET = 1064
EXT_HSRP_GRP_RANGE = 1
EXT_HSRP_GRP_OFFSET = 1064

DEP_ID_REGEX = "(\w{3,3})"
NROUTER_REGEX = "nrouter-(\w{6,6})-" + DEP_ID_REGEX
#NROUTER_REGEX = "nrouter-(\w{6,6})"

VRF_REGEX = "ip vrf " + NROUTER_REGEX
VRF_REGEX_NEW = "vrf definition " + NROUTER_REGEX

INTF_REGEX_BASE = "interface %s\.(\d+)"
INTF_DESC_REGEX = "\s*description OPENSTACK_NEUTRON-" + DEP_ID_REGEX + "_INTF"
VRF_EXT_INTF_REGEX = "\s*ip vrf forwarding .*"
VRF_INTF_REGEX = "\s*ip vrf forwarding " + NROUTER_REGEX
VRF_EXT_INTF_REGEX_NEW = "\s*vrf forwarding .*"
VRF_INTF_REGEX_NEW = "\s*vrf forwarding " + NROUTER_REGEX
DOT1Q_REGEX = "\s*encapsulation dot1Q (\d+)"
INTF_NAT_REGEX = "\s*ip nat (inside|outside)"
HSRP_REGEX = "\s*standby (\d+) .*"

INTF_V4_ADDR_REGEX = "\s*ip address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) " \
                     "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
HSRP_V4_VIP_REGEX = "\s*standby (\d+) ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

SNAT_REGEX = "ip nat inside source static " \
             "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) " \
             "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) vrf " + NROUTER_REGEX + \
             " redundancy neutron-hsrp-(\d+)-(\d+)"

NAT_POOL_REGEX = "ip nat pool " + NROUTER_REGEX + \
                 "_nat_pool (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) " \
                 "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) " \
                 "netmask (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

NAT_OVERLOAD_REGEX_BASE = "ip nat inside source list neutron_acl_" + \
                          DEP_ID_REGEX + "_(\d+) interface %s\.(\d+) vrf " + \
                          NROUTER_REGEX + " overload"
NAT_POOL_OVERLOAD_REGEX = "ip nat inside source list neutron_acl_" + \
                          DEP_ID_REGEX + "_(\d+) pool " + NROUTER_REGEX + \
                          "_nat_pool vrf " + NROUTER_REGEX + " overload"

ACL_REGEX = "ip access-list standard neutron_acl_" + DEP_ID_REGEX + "_(\d+)"
ACL_CHILD_REGEX = "\s*permit (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) " \
                  "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

DEFAULT_ROUTE_REGEX_BASE = "ip route vrf " + NROUTER_REGEX + \
                           " 0\.0\.0\.0 0\.0\.0\.0 %s\.(\d+) " \
                           "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

DEFAULT_ROUTE_V6_REGEX_BASE = "ipv6 route vrf " + NROUTER_REGEX + \
                              " ::/0 %s\.(\d+) ([0-9A-Fa-f:]+) " \
                              "nexthop-vrf default"

TENANT_ROUTE_V6_REGEX_BASE = "ipv6 route ([0-9A-Fa-f:/]+) %s.(\d+) " \
                             "nexthop-vrf " + NROUTER_REGEX
INTF_V6_ADDR_REGEX = "\s*ipv6 address ([0-9A-Fa-f:]+)\/(\d+)"


XML_FREEFORM_SNIPPET = "<config><cli-config-data>%s</cli-config-data></config>"
XML_CMD_TAG = "<cmd>%s</cmd>"


def is_port_v6(port):
    prefix = port['subnet']['cidr']
    if netaddr.IPNetwork(prefix).version == 6:
        return True
    else:
        return False


class ConfigSyncer(object):

    def __init__(self, router_db_info, my_dep_id, other_dep_ids,
                 target_asr_name, target_intf_name):
        router_id_dict, interface_segment_dict, segment_nat_dict = \
            self.process_routers_data(router_db_info)
        self.router_id_dict = router_id_dict
        self.intf_segment_dict = interface_segment_dict
        self.segment_nat_dict = segment_nat_dict
        self.dep_id = my_dep_id
        self.other_dep_ids = other_dep_ids
        self.existing_cfg_dict = {}
        self.target_asr_name = target_asr_name
        self.existing_cfg_dict['interfaces'] = {}
        self.existing_cfg_dict['dyn_nat'] = {}
        self.existing_cfg_dict['static_nat'] = {}
        self.existing_cfg_dict['acls'] = {}
        self.existing_cfg_dict['routes'] = {}
        self.existing_cfg_dict['pools'] = {}
        self.init_regex(target_intf_name)

    def init_regex(self, target_intf_name):
        escape_name = re.escape(target_intf_name)
        self.INTF_REGEX = INTF_REGEX_BASE % escape_name
        self.NAT_OVERLOAD_REGEX = NAT_OVERLOAD_REGEX_BASE % escape_name
        self.DEFAULT_ROUTE_REGEX = DEFAULT_ROUTE_REGEX_BASE % escape_name
        self.DEFAULT_ROUTE_V6_REGEX = DEFAULT_ROUTE_V6_REGEX_BASE % escape_name
        self.TENANT_ROUTE_V6_REGEX = TENANT_ROUTE_V6_REGEX_BASE % escape_name

    def process_routers_data(self, routers):
        router_id_dict = {}
        interface_segment_dict = {}
        segment_nat_dict = {}
        #TODO(onecloud): could combine segment_nat_dict and
        # interface_segment_dict into a single "segment_dict"

        for router in routers:

            # initialize router dict keyed by first 6 characters of router_id
            router_id = router['id'][0:6]
            router_id_dict[router_id] = router

            # initialize interface dict keyed by segment_id
            interfaces = []
            if '_interfaces' in router.keys():
                interfaces += router['_interfaces']

            if 'gw_port' in router.keys():
                interfaces += [router['gw_port']]

            if '_ha_gw_interfaces' in router.keys():
                interfaces += router['_ha_gw_interfaces']

            # Orgnize interfaces, indexed by segment_id
            for interface in interfaces:
                hosting_info = interface['hosting_info']
                segment_id = hosting_info['segmentation_id']
                if segment_id not in interface_segment_dict:
                    interface_segment_dict[segment_id] = []
                    segment_nat_dict[segment_id] = False
                interface_segment_dict[segment_id].append(interface)

            # Mark which segments have NAT enabled
            # i.e., the segment is present on at least 1 router with
            # both external and internal networks present
            if 'gw_port' in router.keys():
                gw_port = router['gw_port']
                gw_segment_id = gw_port['hosting_info']['segmentation_id']
                if '_interfaces' in router.keys():
                    interfaces = router['_interfaces']
                    for intf in interfaces:
                        if intf['device_owner'] == \
                                constants.DEVICE_OWNER_ROUTER_INTF:
                            if not is_port_v6(intf):
                                intf_segment_id = \
                                    intf['hosting_info']['segmentation_id']
                                segment_nat_dict[gw_segment_id] = True
                                segment_nat_dict[intf_segment_id] = True
        return router_id_dict, interface_segment_dict, segment_nat_dict

    def _get_hsrp_grp_num_from_router_id(self, router_id):
        router_id_digits = router_id[:6]
        hsrp_num = int(router_id_digits, 16) % TENANT_HSRP_GRP_RANGE
        hsrp_num += TENANT_HSRP_GRP_OFFSET
        return hsrp_num

    def _get_hsrp_grp_num_from_net_id(self, network_id):
        net_id_digits = network_id[:6]
        hsrp_num = int(net_id_digits, 16) % EXT_HSRP_GRP_RANGE
        hsrp_num += EXT_HSRP_GRP_OFFSET
        return hsrp_num

    def delete_invalid_cfg(self, conn):
        router_id_dict = self.router_id_dict
        intf_segment_dict = self.intf_segment_dict
        segment_nat_dict = self.segment_nat_dict

        for router_id, router in router_id_dict.iteritems():
            #LOG.info("ROUTER ID: %s   DATA: %s\n\n" % (router_id, router))
            LOG.info(_("ROUTER_ID: %s"), router_id)

        LOG.info(_("\n"))

        for segment_id, intf_list in intf_segment_dict.iteritems():
            LOG.info(_("SEGMENT_ID: %s"), segment_id)
            for intf in intf_list:
                dev_owner = intf['device_owner']
                dev_id = intf['device_id'][0:6]
                ip_addr = intf['fixed_ips'][0]['ip_address']
                if 'phy_router_db' in intf.keys():
                    phy_router_name = intf['phy_router_db']['name']
                    LOG.info(_("    INTF: %(ip_addr)s, %(dev_id)s, "
                               "%(dev_owner)s, %(phy_router_name)s"),
                             {'ip_addr': ip_addr,
                              'dev_id': dev_id,
                              'dev_owner': dev_owner,
                              'phy_router_name': phy_router_name})
                else:
                    LOG.info(_("    INTF: %(ip_addr)s, %(dev_id)s, "
                               "%(dev_owner)s"), {'ip_addr': ip_addr,
                                                  'dev_id': dev_id,
                                                  'dev_owner': dev_owner})

        running_cfg = self.get_running_config(conn)
        parsed_cfg = ciscoconfparse.CiscoConfParse(running_cfg)

        self.clean_snat(conn, router_id_dict, intf_segment_dict,
                        segment_nat_dict, parsed_cfg)
        self.clean_nat_pool_overload(conn, router_id_dict, intf_segment_dict,
                                     segment_nat_dict, parsed_cfg)
        self.clean_nat_pool(conn, router_id_dict, intf_segment_dict,
                            segment_nat_dict, parsed_cfg)
        self.clean_default_route(conn, router_id_dict, intf_segment_dict,
                                 segment_nat_dict,
                                 parsed_cfg, self.DEFAULT_ROUTE_REGEX)
        self.clean_default_route(conn, router_id_dict, intf_segment_dict,
                                 segment_nat_dict,
                                 parsed_cfg, self.DEFAULT_ROUTE_V6_REGEX)
        self.clean_acls(conn, intf_segment_dict, segment_nat_dict, parsed_cfg)
        self.clean_interfaces(conn, intf_segment_dict, segment_nat_dict,
                              parsed_cfg)
        self.clean_vrfs(conn, router_id_dict, parsed_cfg)

    def get_running_config(self, conn):
        """Get the CSR's current running config.

        :return: Current IOS running config as multiline string
        """
        config = conn.get_config(source="running")
        if config:
            root = ET.fromstring(config._raw)
            running_config = root[0][0]
            rgx = re.compile("\r*\n+")
            ioscfg = rgx.split(running_config.text)
            return ioscfg

    def get_ostk_router_ids(self, router_id_dict):
        ostk_router_ids = []
        for router_id, router in router_id_dict.iteritems():
            ostk_router_ids.append(router_id)
        return ostk_router_ids

    def get_running_config_router_ids(self, parsed_cfg):
        rconf_ids = []
        invalid_dep_id_list = []

        for parsed_obj in parsed_cfg.find_objects(VRF_REGEX_NEW):
            LOG.info(_("VRF object: %s"), parsed_obj)
            match_obj = re.match(VRF_REGEX_NEW, parsed_obj.text)
            router_id, dep_id = match_obj.group(1, 2)
            LOG.info(_("    First 6 digits of router ID: %(router_id)s, "
                       "dep_id: %(dep_id)s\n"),
                     {'router_id': router_id,
                      'dep_id': dep_id})
            if dep_id == self.dep_id:
                rconf_ids.append(router_id)
            elif dep_id not in self.other_dep_ids:
                invalid_dep_id_list.append((router_id, dep_id))

        return rconf_ids, invalid_dep_id_list

    def clean_vrfs(self, conn, router_id_dict, parsed_cfg):

        ostk_router_ids = self.get_ostk_router_ids(router_id_dict)
        rconf_ids, invalid_routers = \
            self.get_running_config_router_ids(parsed_cfg)

        source_set = set(ostk_router_ids)
        dest_set = set(rconf_ids)

        add_set = source_set.difference(dest_set)
        del_set = dest_set.difference(source_set)

        LOG.info(_("VRF DB set: %s"), source_set)
        LOG.info(_("VRFs to delete: %s"), del_set)
        LOG.info(_("VRFs to add: %s"), add_set)

        for router_id in del_set:
            vrf_name = "nrouter-%s-%s" % (router_id, self.dep_id)
            confstr = asr_snippets.REMOVE_VRF_DEFN % vrf_name
            conn.edit_config(target='running', config=confstr)

        for router_id, dep_id in invalid_routers:
            vrf_name = "nrouter-%s-%s" % (router_id, dep_id)
            confstr = asr_snippets.REMOVE_VRF_DEFN % vrf_name
            conn.edit_config(target='running', config=confstr)

        for router_id in add_set:
            vrf_name = "nrouter-%s-%s" % (router_id, self.dep_id)
            asr_snippets.CREATE_VRF_DEFN % vrf_name
            #rpc_obj = conn.edit_config(target='running', config=confstr)

    def get_single_cfg(self, cfg_line):
        if len(cfg_line) != 1:
            return None
        else:
            return cfg_line[0]

    def clean_nat_pool(self, conn, router_id_dict,
                       intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_pool_list = []
        pools = parsed_cfg.find_objects(NAT_POOL_REGEX)
        for pool in pools:
            LOG.info(_("\nNAT pool: %s"), pool)
            match_obj = re.match(NAT_POOL_REGEX, pool.text)
            router_id, dep_id, start_ip, end_ip, netmask = \
                match_obj.group(1, 2, 3, 4, 5)

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_pool_list.append(pool.text)
                    continue
                else:
                    # some other deployment owns this route, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for NAT pool, deleting"))
                delete_pool_list.append(pool.text)
                continue

            # Check that router has external network
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info(_("router has no gw_port, pool is invalid, deleting"))
                delete_pool_list.append(pool.text)
                continue

            # Check IPs and netmask
            gw_port = router['gw_port']
            gw_ip = gw_port['fixed_ips'][0]['ip_address']
            pool_net = netaddr.IPNetwork(gw_port['subnet']['cidr'])
            if start_ip != gw_ip:
                LOG.info(_("start IP for pool does not match, deleting"))
                delete_pool_list.append(pool.text)
                continue

            if end_ip != gw_ip:
                LOG.info(_("end IP for pool does not match, deleting"))
                delete_pool_list.append(pool.text)
                continue

            if netmask != str(pool_net.netmask):
                LOG.info(_("netmask for pool does not match, "
                           "netmask:%(netmask)s, "
                           "pool_netmask:%(pool_net.netmask)s, deleting"),
                         {"netmask": netmask,
                          "pool_net.netmask": pool_net.netmask})
                delete_pool_list.append(pool.text)
                continue
            self.existing_cfg_dict['pools'][gw_ip] = pool

        for pool_cfg in delete_pool_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (pool_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete pool: %s"), del_cmd)
            conn.edit_config(target='running', config=confstr)

    def clean_tenant_v6_route(self, conn, router_id_dict,
                              intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_route_list = []
        tenant_routes = parsed_cfg.find_objects(self.TENANT_ROUTE_V6_REGEX)
        for route in tenant_routes:
            LOG.info(_("tenant route: %s"), route)
            match_obj = re.match(self.TENANT_ROUTE_V6_REGEX, route.text)
            prefix, segment_id, router_id, dep_id = \
                match_obj.group(1, 2, 3, 4)
            LOG.info(_("    prefix: %(prefix)s, segment_id: %(segment_id)s, "
                       "router_id: %(router_id)s, next_hop: %(dep_id)s"),
                     {"prefix": prefix, "segment_id": segment_id,
                      "router_id": router_id, "dep_id": dep_id})

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_route_list.append(route.text)
                    continue
                else:
                    # some other deployment owns this route, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for route, deleting"))
                delete_route_list.append(route.text)
                continue

            router = router_id_dict[router_id]

            # Check that router has internal network interface on segment_id
            intf_match_found = False
            for intf in router['_interfaces']:
                if intf['device_owner'] == constants.DEVICE_OWNER_ROUTER_INTF:
                    intf_segment_id = intf['hosting_info']['segmentation_id']
                    if intf_segment_id == segment_id:
                        intf_match_found = True
                        break

            if intf_match_found is False:
                LOG.info(_("router does not have this "
                           "internal network assigned, deleting rule"))
                delete_route_list.append(route.text)
                continue

            db_intf = intf_segment_dict[intf.segment_id][0]
            target_prefix = netaddr.IPNetwork(db_intf['subnet']['cidr'])
            actual_prefix = netaddr.IPNetwork(prefix)
            if target_prefix != actual_prefix:
                LOG.info(_("Tenant route has incorrect prefix, deleting"))
                delete_route_list.append(route.text)
                continue

        for route_cfg in delete_route_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (route_cfg))
            # confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete tenant route: %s"), del_cmd)

        return

    def clean_default_route(self, conn, router_id_dict, intf_segment_dict,
                            segment_nat_dict, parsed_cfg, route_regex):
        delete_route_list = []
        default_routes = parsed_cfg.find_objects(route_regex)
        for route in default_routes:
            LOG.info(_("\ndefault route: %s"), route)
            match_obj = re.match(route_regex, route.text)
            router_id, dep_id, segment_id, next_hop = \
                match_obj.group(1, 2, 3, 4)
            segment_id = int(segment_id)
            LOG.info(_("    router_id: %(router_id)s, segment_id: "
                       "%(segment_id)s, next_hop: %(next_hop)s"),
                     {"router_id": router_id,
                      "segment_id": segment_id,
                      "next_hop": next_hop})

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_route_list.append(route.text)
                    continue
                else:
                    # some other deployment owns this route, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for route, deleting"))
                delete_route_list.append(route.text)
                continue

            # Check that router has external network and segment_id matches
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info(_("router has no gw_port, "
                           "route is invalid, deleting"))
                delete_route_list.append(route.text)
                continue

            gw_port = router['gw_port']
            gw_segment_id = gw_port['hosting_info']['segmentation_id']
            if segment_id != gw_segment_id:
                LOG.info(_("route segment_id does not match "
                           "router's gw segment_id, deleting"))
                delete_route_list.append(route.text)
                continue

            # Check that nexthop matches gw_ip of external network
            gw_ip = gw_port['subnet']['gateway_ip']
            if next_hop.lower() != gw_ip.lower():
                LOG.info(_("route has incorrect next-hop, deleting"))
                delete_route_list.append(route.text)
                continue

            self.existing_cfg_dict['routes'][router_id] = route

        for route_cfg in delete_route_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (route_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete default route: %s"), del_cmd)
            conn.edit_config(target='running', config=confstr)

    def clean_snat(self, conn, router_id_dict, intf_segment_dict,
                   segment_nat_dict, parsed_cfg):
        delete_fip_list = []
        floating_ip_nats = parsed_cfg.find_objects(SNAT_REGEX)
        for snat_rule in floating_ip_nats:
            LOG.info(_("\nstatic nat rule: %s"), (snat_rule))
            match_obj = re.match(SNAT_REGEX, snat_rule.text)
            inner_ip, outer_ip, router_id, dep_id, hsrp_num, segment_id = \
                match_obj.group(1, 2, 3, 4, 5, 6)
            segment_id = int(segment_id)
            hsrp_num = int(hsrp_num)
            LOG.info(_("   in_ip: %(inner_ip)s, out_ip: %(outer_ip)s, "
                       "router_id: %(router_id)s, dep_id: %(dep_id)s, "
                       "hsrp_num: %(hsrp_num)s, segment_id: %(segment_id)s"),
                     {"inner_ip": inner_ip, "outer_ip": outer_ip,
                      "router_id": router_id, "dep_id": dep_id,
                      "hsrp_num": hsrp_num, "segment_id": segment_id})

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_fip_list.append(snat_rule.text)
                    continue
                else:
                    # some other deployment owns this rule, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for rule, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            # Check that router has external network and segment_id matches
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info(_("router has no gw_port, snat is invalid, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            # Check that hsrp group name is correct
            gw_port = router['gw_port']
            gw_net_id = gw_port['network_id']
            gw_hsrp_num = self._get_hsrp_grp_num_from_net_id(gw_net_id)
            gw_segment_id = gw_port['hosting_info']['segmentation_id']
            if segment_id != gw_segment_id:
                LOG.info(_("snat segment_id does not match "
                           "router's gw segment_id, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            if hsrp_num != gw_hsrp_num:
                LOG.info(_("snat hsrp group does not match router "
                           "gateway's hsrp group, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            # Check that in,out ip pair matches a floating_ip defined on router
            if '_floatingips' not in router:
                LOG.info(_("Router has no floating IPs defined, "
                           "snat rule is invalid, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            fip_match_found = False
            for floating_ip in router['_floatingips']:
                if inner_ip == floating_ip['fixed_ip_address'] and \
                   outer_ip == floating_ip['floating_ip_address']:
                    fip_match_found = True
                    break
            if fip_match_found is False:
                LOG.info(_("snat rule does not match defined "
                           "floating IPs, deleting"))
                delete_fip_list.append(snat_rule.text)
                continue

            self.existing_cfg_dict['static_nat'][outer_ip] = snat_rule

        for fip_cfg in delete_fip_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (fip_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete SNAT: %s"), del_cmd)
            conn.edit_config(target='running', config=confstr)

    def clean_nat_pool_overload(self, conn, router_id_dict, intf_segment_dict,
                                segment_nat_dict, parsed_cfg):
        delete_nat_list = []
        nat_overloads = parsed_cfg.find_objects(NAT_POOL_OVERLOAD_REGEX)
        for nat_rule in nat_overloads:
            LOG.info(_("\nnat overload rule: %s"), nat_rule)
            match_obj = re.match(NAT_POOL_OVERLOAD_REGEX, nat_rule.text)
            acl_dep_id, segment_id, pool_router_id, \
                pool_dep_id, router_id, dep_id = match_obj.group(1, 2, 3, 4,
                                                                 5, 6)

            segment_id = int(segment_id)

            if acl_dep_id != dep_id:
                delete_nat_list.append(nat_rule.text)

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_nat_list.append(nat_rule.text)
                    continue
                else:
                    # some other deployment owns this rule, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for rule, deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that correct pool is specified
            if pool_router_id != router_id:
                LOG.info(_("Pool and VRF name mismatch, deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            if pool_dep_id != dep_id:
                LOG.info(_("Pool and VRF deployment ID mismatch, deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that router has external network
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info(_("router has no gw_port, "
                         "nat overload is invalid, deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that router has internal network interface on segment_id
            intf_match_found = False
            for intf in router.get(constants.INTERFACE_KEY, []):
                if intf['device_owner'] == constants.DEVICE_OWNER_ROUTER_INTF:
                    intf_segment_id = intf['hosting_info']['segmentation_id']
                    if intf_segment_id == segment_id:
                        intf_match_found = True
                        break
            if intf_match_found is False:
                LOG.info(_("router does not have this internal "
                           "network assigned, deleting rule"))
                delete_nat_list.append(nat_rule.text)
                continue

            self.existing_cfg_dict['dyn_nat'][segment_id] = nat_rule

        for nat_cfg in delete_nat_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (nat_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete NAT overload: %s"), del_cmd)
            conn.edit_config(target='running', config=confstr)

    # For 'interface' style NAT overload, was previously used but not anymore
    def clean_nat_overload(self, conn, router_id_dict, intf_segment_dict,
                           segment_nat_dict, parsed_cfg):
        delete_nat_list = []
        nat_overloads = parsed_cfg.find_objects(self.NAT_OVERLOAD_REGEX)
        for nat_rule in nat_overloads:
            LOG.info(_("\nnat overload rule: %s"), nat_rule)
            match_obj = re.match(self.NAT_OVERLOAD_REGEX, nat_rule.text)
            acl_dep_id, segment_id, intf_segment_id, router_id, dep_id = \
                match_obj.group(1, 2, 3, 4, 5)

            segment_id = int(segment_id)
            intf_segment_id = int(intf_segment_id)

            if acl_dep_id != dep_id:
                delete_nat_list.append(nat_rule.text)

            # Check deployment_id
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_nat_list.append(nat_rule.text)
                    continue
                else:
                    # some other deployment owns this rule, don't touch
                    continue

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info(_("router not found for rule, deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that router has external network
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info(_("router has no gw_port, nat overload is invalid, "
                         "deleting"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that external network interface segment_id matches
            gw_port = router['gw_port']
            ext_intf_segment_id = gw_port['hosting_info']['segmentation_id']
            if ext_intf_segment_id != intf_segment_id:
                LOG.info(_("outbound external interface segment_id is "
                           "wrong, deleting rule"))
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that router has internal network interface on segment_id
            intf_match_found = False
            for intf in router['_interfaces']:
                if intf['device_owner'] == constants.DEVICE_OWNER_ROUTER_INTF:
                    intf_segment_id = intf['hosting_info']['segmentation_id']
                    if intf_segment_id == segment_id:
                        intf_match_found = True
                        break
            if intf_match_found is False:
                LOG.info(_("router does not have this internal network "
                           "assigned, deleting rule"))
                delete_nat_list.append(nat_rule.text)
                continue

            self.existing_cfg_dict['dyn_nat'][segment_id] = nat_rule

        for nat_cfg in delete_nat_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (nat_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            conn.edit_config(target='running', config=confstr)

    def check_acl_permit_rules_valid(self, segment_id, acl, intf_segment_dict):
        permit_rules = acl.re_search_children(ACL_CHILD_REGEX)
        for permit_rule in permit_rules:
            LOG.info(_("   permit rule: %s"), permit_rule)
            match_obj = re.match(ACL_CHILD_REGEX, permit_rule.text)
            net_ip, hostmask = match_obj.group(1, 2)

            cfg_subnet = netaddr.IPNetwork("%s/%s" % (net_ip, hostmask))
            # dummy value
            db_subnet = netaddr.IPNetwork("255.255.255.255/32")
            try:
                intf_list = intf_segment_dict[segment_id]
                for intf in intf_list:
                    if intf['device_owner'] == \
                            constants.DEVICE_OWNER_ROUTER_INTF:
                        subnet_cidr = intf['subnet']['cidr']
                        db_subnet = netaddr.IPNetwork(subnet_cidr)
                        break
            except KeyError:
                LOG.info(_("KeyError when attemping to validate segment_id"))
                return False

            LOG.info(_("   cfg_subnet: %(cfg_net)s/%(cfg_prefix)s, "
                       "db_subnet: %(subnet)s/%(subnet_prefix)s"),
                     {'cfg_net': cfg_subnet.network,
                      'cfg_prefix': cfg_subnet.prefixlen,
                      'subnet': db_subnet.network,
                      'subnet_prefix': db_subnet.prefixlen})

            if cfg_subnet.network != db_subnet.network or \
               cfg_subnet.prefixlen != db_subnet.prefixlen:
                LOG.info(_("ACL subnet does not match subnet info in "
                           "openstack DB, deleting ACL"))
                return False

        return True

    def clean_acls(self, conn, intf_segment_dict, segment_nat_dict,
                   parsed_cfg):
        delete_acl_list = []
        acls = parsed_cfg.find_objects(ACL_REGEX)
        for acl in acls:
            LOG.info(_("\nacl: %s"), acl)
            match_obj = re.match(ACL_REGEX, acl.text)
            dep_id, segment_id = match_obj.group(1, 2)
            segment_id = int(segment_id)
            LOG.info(_("   dep_id: %(dep_id)s segment_id: %(segment_id)s"),
                     {"dep_id": dep_id,
                      "segment_id": segment_id})

            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    delete_acl_list.append(acl.text)
                    continue
                else:
                    # some other deployment owns this ACL, don't touch
                    continue

            # Check that segment_id exists in openstack DB info
            if segment_id not in intf_segment_dict:
                LOG.info(_("Segment ID not found, deleting acl"))
                delete_acl_list.append(acl.text)
                continue

            # Check that permit rules match subnets defined on openstack intfs
            if self.check_acl_permit_rules_valid(segment_id, acl,
                                                 intf_segment_dict) is False:
                delete_acl_list.append(acl.text)
                continue

            self.existing_cfg_dict['acls'][segment_id] = acl

        for acl_cfg in delete_acl_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (acl_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Delete ACL: %s"), del_cmd)
            conn.edit_config(target='running', config=confstr)

    def subintf_real_ip_check(self, intf_list, is_external, ip_addr, netmask):

        if is_external:
            target_type = constants.DEVICE_OWNER_ROUTER_HA_GW
        else:
            target_type = constants.DEVICE_OWNER_ROUTER_HA_INTF

        for target_intf in intf_list:
            if target_intf['device_owner'] == target_type:
                asr_name = target_intf['phy_router_db']['name']
                if asr_name == self.target_asr_name:
                    target_ip = target_intf['fixed_ips'][0]['ip_address']
                    target_net = \
                        netaddr.IPNetwork(target_intf['subnet']['cidr'])
                    LOG.info(_("target ip,net: %(target_ip)s,%(target_net)s,"
                               "actual ip,net %(ip_addr)s,%(netmask)s"),
                             {'target_ip': target_ip, 'target_net': target_net,
                              'ip_addr': ip_addr, 'netmask': netmask})
                    if ip_addr != target_ip:
                        LOG.info(_("Subintf real IP is incorrect, deleting"))
                        return False
                    if netmask != str(target_net.netmask):
                        LOG.info(_("Subintf has incorrect netmask, deleting"))
                        return False

                    return True

        return False

    def subintf_real_ipv6_check(self, intf_list, is_external, ipv6_addr,
                                prefixlen):

        if is_external:
            target_type = constants.DEVICE_OWNER_ROUTER_GW
        else:
            target_type = constants.DEVICE_OWNER_ROUTER_INTF

        for target_intf in intf_list:
            if target_intf['device_owner'] == target_type:

                target_ip = netaddr.IPAddress(
                    target_intf['fixed_ips'][0]['ip_address']
                )
                target_prefixlen = netaddr.IPNetwork(
                    target_intf['subnet']['cidr']
                ).prefixlen

                LOG.info(_("target ip,prefixlen: "
                         "%(target_ip)s,%(target_prefixlen)s, "
                         "actual ip,prefixlen %(ipv6_addr)s,%(prefixlen)s"),
                         {'target_ip': target_ip,
                          'target_prefixlen': target_prefixlen,
                          'ipv6_addr': ipv6_addr,
                          'prefixlen': prefixlen})

                if target_ip != netaddr.IPAddress(ipv6_addr):
                    LOG.info(_("Subintf IPv6 addr is incorrect, deleting"))
                    return False

                if target_prefixlen != int(prefixlen):
                    LOG.info(_("Subintf IPv6 prefix length is "
                               "incorrect, deleting"))
                    return False

                return True

        return False

    def subintf_hsrp_ip_check(self, intf_list, is_external, ip_addr):
        if is_external:
            target_type = constants.DEVICE_OWNER_ROUTER_GW
        else:
            target_type = constants.DEVICE_OWNER_ROUTER_INTF

        for target_intf in intf_list:
            if target_intf['device_owner'] == target_type:
                if is_external:
                    if target_intf['device_id'] == "PHYSICAL_GLOBAL_ROUTER_ID":
                        target_ip = target_intf['fixed_ips'][0]['ip_address']
                        LOG.info(_("target_ip: %(target_ip)s, "
                                   "actual_ip: %(ip_addr)s"),
                                 {'target_ip': target_ip, 'ip_addr': ip_addr})
                        if ip_addr != target_ip:
                            LOG.info(_("HSRP VIP mismatch, deleting"))
                            return False

                        return True
                else:
                    target_ip = target_intf['fixed_ips'][0]['ip_address']
                    LOG.info(_("target_ip: %(target_ip)s, "
                               "actual_ip: %(ip_addr)s"),
                             {'target_ip': target_ip, 'ip_addr': ip_addr})
                    if ip_addr != target_ip:
                        LOG.info(_("HSRP VIP mismatch, deleting"))
                        return False

                    return True

        return False

    # Returns True if interface has correct NAT config
    def clean_interfaces_nat_check(self, intf, segment_nat_dict):
        intf_nat_type = intf.re_search_children(INTF_NAT_REGEX)
        intf_nat_type = self.get_single_cfg(intf_nat_type)

        if intf_nat_type is not None:
            intf_nat_type = intf_nat_type.re_match(INTF_NAT_REGEX, group=1)

        LOG.info(_("NAT Type: %s"), intf_nat_type)

        intf.nat_type = intf_nat_type

        if segment_nat_dict[intf.segment_id]:
            if intf.is_external:
                if intf_nat_type != "outside":
                    nat_cmd = XML_CMD_TAG % (intf.text)
                    nat_cmd += XML_CMD_TAG % ("ip nat outside")
                    # confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                    LOG.info(_("NAT type mismatch, should be outside"))
                    return False
            else:
                if intf_nat_type != "inside":
                    nat_cmd = XML_CMD_TAG % (intf.text)
                    nat_cmd += XML_CMD_TAG % ("ip nat inside")
                    # confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                    LOG.info(_("NAT type mismatch, should be inside"))
                    return False
        else:
            if intf_nat_type is not None:
                nat_cmd = XML_CMD_TAG % (intf.text)
                nat_cmd += XML_CMD_TAG % ("no ip nat %s" % (intf_nat_type))
                # confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                LOG.info(_("NAT type mismatch, should have no NAT"))
                return False

        return True

    def clean_interfaces_ipv4_hsrp_check(self, intf, intf_segment_dict):
        # Check HSRP VIP
        hsrp_vip_cfg_list = intf.re_search_children(HSRP_V4_VIP_REGEX)
        if len(hsrp_vip_cfg_list) < 1:
            LOG.info(_("Intferace is missing HSRP VIP, deleting"))
            return False

        hsrp_vip_cfg = hsrp_vip_cfg_list[0]
        match_obj = re.match(HSRP_V4_VIP_REGEX, hsrp_vip_cfg.text)
        hsrp_vip_grp_num, hsrp_vip = match_obj.group(1, 2)
        return self.subintf_hsrp_ip_check(intf_segment_dict[intf.segment_id],
                                          intf.is_external,
                                          hsrp_vip)

    def clean_interfaces_ipv4_check(self, intf, intf_segment_dict):
        # Check that real IP address is correct
        ipv4_addr = intf.re_search_children(INTF_V4_ADDR_REGEX)
        if len(ipv4_addr) < 1:
            LOG.info(_("Subintf has no IP address, deleting"))
            return False

        ipv4_addr_cfg = ipv4_addr[0]
        match_obj = re.match(INTF_V4_ADDR_REGEX, ipv4_addr_cfg.text)
        ip_addr, netmask = match_obj.group(1, 2)

        return self.subintf_real_ip_check(intf_segment_dict[intf.segment_id],
                                          intf.is_external,
                                          ip_addr, netmask)

    def clean_interfaces_ipv6_check(self, intf, intf_segment_dict):
        # Check that real IP address is correct
        ipv6_addr = intf.re_search_children(INTF_V6_ADDR_REGEX)
        if len(ipv6_addr) < 1:
            LOG.info(_("Subintf has no IPv6 address, deleting"))
            return False

        ipv6_addr_cfg = ipv6_addr[0]
        match_obj = re.match(INTF_V6_ADDR_REGEX, ipv6_addr_cfg.text)
        ipv6_addr, prefixlen = match_obj.group(1, 2)

        return self.subintf_real_ipv6_check(intf_segment_dict[intf.segment_id],
                                            intf.is_external,
                                            ipv6_addr, prefixlen)

    def clean_interfaces(self, conn, intf_segment_dict, segment_nat_dict,
                         parsed_cfg):
        runcfg_intfs = [obj for obj in parsed_cfg.find_objects("^interf")
                        if obj.re_search_children(INTF_DESC_REGEX)]

        #LOG.info("intf_segment_dict: %s" % (intf_segment_dict))
        pending_delete_list = []

        # TODO(onecloud): split this big function into smaller functions
        for intf in runcfg_intfs:
            LOG.info(_("\nOpenstack interface: %s"), intf)
            intf.segment_id = int(intf.re_match(self.INTF_REGEX, group=1))
            LOG.info(_("  segment_id: %s"), intf.segment_id)

            # Delete any interfaces where config doesn't match DB
            # Correct config will be added after clearing invalid cfg

            # TODO(onecloud): Check that interface name (e.g. Port-channel10)
            #       matches that specified in .ini file

            # Check deployment_id
            description = intf.re_search_children(INTF_DESC_REGEX)
            description = self.get_single_cfg(description)
            dep_id = description.re_match(INTF_DESC_REGEX, group=1)
            if dep_id != self.dep_id:
                if dep_id not in self.other_dep_ids:
                    # no one owns this, delete
                    pending_delete_list.append(intf)
                    continue
                else:
                    # some other deployment owns this intf, don't touch
                    continue

            # Check that the interface segment_id exists in the current DB data
            if intf.segment_id not in intf_segment_dict:
                LOG.info(_("Invalid segment ID, delete interface"))
                pending_delete_list.append(intf)
                continue

            # Check if dot1q config is correct
            dot1q_cfg = intf.re_search_children(DOT1Q_REGEX)
            dot1q_cfg = self.get_single_cfg(dot1q_cfg)

            if dot1q_cfg is None:
                LOG.info(_("Missing DOT1Q config, delete interface"))
                pending_delete_list.append(intf)
                continue
            else:
                dot1q_num = int(dot1q_cfg.re_match(DOT1Q_REGEX, group=1))
                if dot1q_num != intf.segment_id:
                    LOG.info(_("DOT1Q mismatch, delete interface"))
                    pending_delete_list.append(intf)
                    continue

            # Is this an "external network" segment_id?
            db_intf = intf_segment_dict[intf.segment_id][0]
            intf_type = db_intf["device_owner"]
            intf.is_external = \
                (intf_type == constants.DEVICE_OWNER_ROUTER_HA_GW or
                 intf_type == constants.DEVICE_OWNER_ROUTER_GW)
            intf.has_ipv6 = is_port_v6(db_intf)

            # Check VRF config
            if intf.is_external:
                vrf_cfg = intf.re_search_children(VRF_EXT_INTF_REGEX_NEW)
                vrf_cfg = self.get_single_cfg(vrf_cfg)
                LOG.info(_("VRF: %s"), vrf_cfg)
                # external network has no vrf
                if vrf_cfg is not None:
                    LOG.info(_("External network shouldn't have VRF,"
                               "deleting intf"))
                    pending_delete_list.append(intf)
                    continue
            else:
                vrf_cfg = intf.re_search_children(VRF_INTF_REGEX_NEW)
                vrf_cfg = self.get_single_cfg(vrf_cfg)
                LOG.info(_("VRF: %s"), vrf_cfg)
                if not vrf_cfg:
                    LOG.info(_("Internal network missing valid VRF,"
                               "deleting intf"))
                    pending_delete_list.append(intf)
                    continue

                # check for VRF mismatch
                match_obj = re.match(VRF_INTF_REGEX_NEW, vrf_cfg.text)
                router_id, dep_id = match_obj.group(1, 2)
                if dep_id != self.dep_id:
                    LOG.info(_("Deployment ID mismatch, deleting intf"))
                    pending_delete_list.append(intf)
                    continue
                if router_id != db_intf["device_id"][0:6]:
                    LOG.info(_("Internal network VRF mismatch, deleting intf, "
                               "router_id: %(router_id)s, "
                               "db_intf_dev_id: %(device_id)s"),
                             {'router_id': router_id,
                              'device_id': db_intf["device_id"]})
                    pending_delete_list.append(intf)
                    continue

            # self.existing_cfg_dict['interfaces'][intf.segment_id] = intf

            if intf.is_external:
                correct_grp_num = \
                    self._get_hsrp_grp_num_from_net_id(db_intf['network_id'])
            else:
                correct_grp_num = \
                    self._get_hsrp_grp_num_from_router_id(db_intf['device_id'])

            if not intf.has_ipv6:
                if not self.clean_interfaces_nat_check(intf, segment_nat_dict):
                    pending_delete_list.append(intf)
                    continue
                if not self.clean_interfaces_ipv4_check(intf,
                                                        intf_segment_dict):
                    pending_delete_list.append(intf)
                    continue
                if not self.clean_interfaces_ipv4_hsrp_check(
                        intf, intf_segment_dict):
                    pending_delete_list.append(intf)
                    continue
            else:
                if not self.clean_interfaces_ipv6_check(intf,
                                                        intf_segment_dict):
                    pending_delete_list.append(intf)
                    continue

            # Delete if there's any hsrp config with wrong group number
            # del_hsrp_cmd = XML_CMD_TAG % (intf.text)
            hsrp_cfg_list = intf.re_search_children(HSRP_REGEX)
            needs_hsrp_delete = False
            for hsrp_cfg in hsrp_cfg_list:
                hsrp_num = int(hsrp_cfg.re_match(HSRP_REGEX, group=1))
                if hsrp_num != correct_grp_num:
                    needs_hsrp_delete = True
                    #del_hsrp_cmd += XML_CMD_TAG % ("no %s" % (hsrp_cfg.text))

            if needs_hsrp_delete:
                LOG.info(_("Bad HSRP config for interface, deleting"))
                pending_delete_list.append(intf)
                continue
                #confstr = XML_FREEFORM_SNIPPET % (del_hsrp_cmd)
                #LOG.info("Deleting bad HSRP config: %s" % (confstr))
                #rpc_obj = conn.edit_config(target='running', config=confstr)

            self.existing_cfg_dict['interfaces'][intf.segment_id] = intf.text

        for intf in pending_delete_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (intf.text))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info(_("Deleting %s"), intf.text)
            conn.edit_config(target='running', config=confstr)
