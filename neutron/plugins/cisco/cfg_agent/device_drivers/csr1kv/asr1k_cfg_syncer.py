import re
import xml.etree.ElementTree as ET
import ciscoconfparse
import netaddr
from neutron.common import constants

from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

VRF_REGEX = "ip vrf nrouter-(\w{6,6})"
VRF_EXT_INTF_REGEX = "ip vrf forwarding .*"
VRF_INTF_REGEX = "ip vrf forwarding nrouter-(\w{6,6})"
INTF_REGEX = "interface Port-channel(\d+)\.(\d+)"
DOT1Q_REGEX = "encapsulation dot1Q (\d+)"
INTF_NAT_REGEX = "ip nat (inside|outside)"
HSRP_REGEX = "standby (\d+) .*"
SNAT_REGEX = "ip nat inside source static (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) vrf nrouter-(\w{6,6}) redundancy neutron-hsrp-grp-(\d+)"
# IP_NAT_REGEX = "ip nat inside source static (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) vrf \w+ redundancy \w+"
NAT_OVERLOAD_REGEX = "ip nat inside source list neutron_acl_(\d+) interface Port-channel(\d+)\.(\d+) vrf nrouter-(\w+) overload"
ACL_REGEX = "ip access-list standard neutron_acl_(\d+)"
ACL_CHILD_REGEX = "\s*permit (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
DEFAULT_ROUTE_REGEX = "ip route vrf nrouter-(\w{6,6}) 0\.0\.0\.0 0\.0\.0\.0 Port-channel(\d+)\.(\d+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"


XML_FREEFORM_SNIPPET = "<config><cli-config-data>%s</cli-config-data></config>"
XML_CMD_TAG = "<cmd>%s</cmd>"

class ConfigSyncer(object):

    def __init__(self, router_db_info):
        router_id_dict, interface_segment_dict, segment_nat_dict = self.process_routers_data(router_db_info)
        self.router_id_dict = router_id_dict
        self.intf_segment_dict = interface_segment_dict
        self.segment_nat_dict = segment_nat_dict

    def process_routers_data(self, routers):
        router_id_dict = {}
        interface_segment_dict = {}
        segment_nat_dict = {}
        #TODO: could combine segment_nat_dict and interface_segment_dict
        #      into a single "segment_dict"

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
                        if intf['device_owner'] == constants.DEVICE_OWNER_ROUTER_INTF:
                            intf_segment_id = intf['hosting_info']['segmentation_id']
                            segment_nat_dict[gw_segment_id] = True
                            segment_nat_dict[intf_segment_id] = True

            
        return router_id_dict, interface_segment_dict, segment_nat_dict

    def delete_invalid_cfg(self, conn):
        router_id_dict = self.router_id_dict
        intf_segment_dict = self.intf_segment_dict
        segment_nat_dict = self.segment_nat_dict

        LOG.info("*************************")

        for router_id, router in router_id_dict.iteritems():
            #LOG.info("ROUTER ID: %s   DATA: %s\n\n" % (router_id, router))
            LOG.info("ROUTER_ID: %s" % (router_id))

        LOG.info("\n")

        for segment_id, intf_list in intf_segment_dict.iteritems():
            LOG.info("SEGMENT_ID: %s" % (segment_id))
            for intf in intf_list:
                dev_owner = intf['device_owner']
                dev_id = intf['device_id'][0:6]
                ip_addr = intf['fixed_ips'][0]['ip_address']
                if 'phy_router_db' in intf.keys():
                    phy_router_name = intf['phy_router_db']['name']
                    LOG.info("    INTF: %s, %s, %s, %s" % (ip_addr, dev_id, dev_owner, phy_router_name))
                else:
                    LOG.info("    INTF: %s, %s, %s" % (ip_addr, dev_id, dev_owner))

        running_cfg = self.get_running_config(conn)
        parsed_cfg = ciscoconfparse.CiscoConfParse(running_cfg)

        self.clean_vrfs(conn, router_id_dict, parsed_cfg)
        self.clean_interfaces(conn, intf_segment_dict, segment_nat_dict, parsed_cfg)
        self.clean_snat(conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg)
        self.clean_nat_overload(conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg)
        self.clean_default_route(conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg)
        self.clean_acls(conn, intf_segment_dict, segment_nat_dict, parsed_cfg)

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

        for parsed_obj in parsed_cfg.find_objects(VRF_REGEX):
            LOG.info("VRF object: %s" % (parsed_obj))
            router_id = parsed_obj.re_match(VRF_REGEX)
            LOG.info("    First 6 digits of router ID: %s\n" % (router_id))
            rconf_ids.append(router_id)

        return rconf_ids;
    

    def clean_vrfs(self, conn, router_id_dict, parsed_cfg):
        
        ostk_router_ids = self.get_ostk_router_ids(router_id_dict)
        rconf_ids = self.get_running_config_router_ids(parsed_cfg)
        
        source_set = set(ostk_router_ids)
        dest_set = set(rconf_ids)
        
        add_set = source_set.difference(dest_set)
        del_set = dest_set.difference(source_set)
        
        LOG.info("VRF DB set: %s" % (source_set))
        LOG.info("VRFs to delete: %s" % (del_set))
        LOG.info("VRFs to add: %s" % (add_set))
        
        for router_id in del_set:
            vrf_name = "nrouter-%s" % (router_id)
            confstr = snippets.REMOVE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            
        for router_id in add_set:
            vrf_name = "nrouter-%s" % (router_id)
            confstr = snippets.CREATE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)


    def get_single_cfg(self, cfg_line):
        if len(cfg_line) != 1:
            return None
        else:
            return cfg_line[0]

    def clean_default_route(self, conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_route_list = []
        default_routes = parsed_cfg.find_objects(DEFAULT_ROUTE_REGEX)
        for route in default_routes:
            LOG.info("\ndefault route: %s" % (route))
            match_obj = re.match(DEFAULT_ROUTE_REGEX, route.text)
            router_id, intf_num, segment_id, next_hop = match_obj.group(1,2,3,4)
            segment_id = int(segment_id)
            intf_num = int(intf_num)
            LOG.info("    router_id: %s, intf_num: %s, segment_id: %s, next_hop: %s" % (router_id,
                                                                                        intf_num,
                                                                                        segment_id,
                                                                                        next_hop))

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info("router not found for route, deleting")
                delete_route_list.append(route.text)
                continue

            # Check that router has external network and segment_id matches
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info("router has no gw_port, route is invalid, deleting")
                delete_route_list.append(route.text)
                continue
            
            gw_port = router['gw_port']
            gw_segment_id = gw_port['hosting_info']['segmentation_id']
            if segment_id != gw_segment_id:
                LOG.info("route segment_id does not match router's gw segment_id, deleting")
                delete_route_list.append(route.text)
                continue

            # Check that nexthop matches gw_ip of external network
            gw_ip = gw_port['subnet']['gateway_ip']
            if next_hop != gw_ip:
                LOG.info("route has incorrect next-hop, deleting")
                delete_route_list.append(route.text)
                continue

        for route_cfg in delete_route_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (route_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            rpc_obj = conn.edit_config(target='running', config=confstr)



    def clean_snat(self, conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_fip_list = []
        floating_ip_nats = parsed_cfg.find_objects(SNAT_REGEX)
        for snat_rule in floating_ip_nats:
            LOG.info("\nstatic nat rule: %s" % (snat_rule))
            match_obj = re.match(SNAT_REGEX, snat_rule.text)
            inner_ip, outer_ip, router_id, segment_id = match_obj.group(1,2,3,4)
            segment_id = int(segment_id)
            LOG.info("   in_ip: %s, out_ip: %s, router_id: %s, segment_id: %s" % (inner_ip,
                                                                                  outer_ip,
                                                                                  router_id,
                                                                                  segment_id))
            
            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info("router not found for rule, deleting")
                delete_fip_list.append(snat_rule.text)
                continue

            # Check that router has external network and segment_id matches
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info("router has no gw_port, snat is invalid, deleting")
                delete_fip_list.append(snat_rule.text)
                continue
            
            gw_port = router['gw_port']
            gw_segment_id = gw_port['hosting_info']['segmentation_id']
            if segment_id != gw_segment_id:
                LOG.info("snat segment_id does not match router's gw segment_id, deleting")
                delete_fip_list.append(snat_rule.text)
                continue
            
            # Check that in,out ip pair matches a floating_ip defined on router
            if '_floatingips' not in router:
                LOG.info("Router has no floating IPs defined, snat rule is invalid, deleting")
                delete_fip_list.append(snat_rule.text)
                continue

            fip_match_found = False
            for floating_ip in router['_floatingips']:
                if inner_ip == floating_ip['fixed_ip_address'] and \
                   outer_ip == floating_ip['floating_ip_address']:
                    fip_match_found = True
                    break
            if fip_match_found is False:
                LOG.info("snat rule does not match defined floating IPs, deleting")
                delete_fip_list.append(snat_rule.text)
                continue
        
        for fip_cfg in delete_fip_list:
             del_cmd = XML_CMD_TAG % ("no %s" % (fip_cfg))
             confstr = XML_FREEFORM_SNIPPET % (del_cmd)
             rpc_obj = conn.edit_config(target='running', config=confstr)
            
            
    def clean_nat_overload(self, conn, router_id_dict, intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_nat_list = []
        nat_overloads = parsed_cfg.find_objects(NAT_OVERLOAD_REGEX)
        for nat_rule in nat_overloads:
            LOG.info("\nnat overload rule: %s" % (nat_rule))
            match_obj = re.match(NAT_OVERLOAD_REGEX, nat_rule.text)
            segment_id, intf_num, intf_segment_id, router_id = match_obj.group(1,2,3,4)
            
            segment_id = int(segment_id)
            intf_num = int(intf_num)
            intf_segment_id = int(intf_segment_id)

            # Check that VRF exists in openstack DB info
            if router_id not in router_id_dict:
                LOG.info("router not found for rule, deleting")
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that router has external network
            router = router_id_dict[router_id]
            if "gw_port" not in router:
                LOG.info("router has no gw_port, nat overload is invalid, deleting")
                delete_nat_list.append(nat_rule.text)
                continue

            # Check that external network interface segment_id matches
            gw_port = router['gw_port']
            ext_intf_segment_id = gw_port['hosting_info']['segmentation_id']
            if ext_intf_segment_id != intf_segment_id:
                LOG.info("outbound external interface segment_id is wrong, deleting rule")
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
                LOG.info("router does not have this internal network assigned, deleting rule")
                delete_nat_list.append(nat_rule.text)
                continue
            
        for nat_cfg in delete_nat_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (nat_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            

    def check_acl_permit_rules_valid(self, segment_id, acl, intf_segment_dict):
        permit_rules = acl.re_search_children(ACL_CHILD_REGEX)
        for permit_rule in permit_rules:
            LOG.info("   permit rule: %s" % (permit_rule))
            match_obj = re.match(ACL_CHILD_REGEX, permit_rule.text)
            net_ip, hostmask = match_obj.group(1,2)
            
            cfg_subnet = netaddr.IPNetwork("%s/%s" % (net_ip, hostmask))
            
            db_subnet = netaddr.IPNetwork("255.255.255.255/32") # dummy value
            intf_list = intf_segment_dict[segment_id]
            for intf in intf_list:
                if intf['device_owner'] == constants.DEVICE_OWNER_ROUTER_INTF:
                    subnet_cidr = intf['subnet']['cidr']
                    db_subnet = netaddr.IPNetwork(subnet_cidr)
                    break

            LOG.info("   cfg_subnet: %s/%s, db_subnet: %s/%s" % (cfg_subnet.network,
                                                           cfg_subnet.prefixlen,
                                                           db_subnet.network,
                                                           db_subnet.prefixlen))
            if cfg_subnet.network != db_subnet.network or \
               cfg_subnet.prefixlen != db_subnet.prefixlen:
                LOG.info("ACL subnet does not match subnet info in openstack DB, deleting ACL")
                return False
        
        return True

    def clean_acls(self, conn, intf_segment_dict, segment_nat_dict, parsed_cfg):
        delete_acl_list = []
        acls = parsed_cfg.find_objects(ACL_REGEX)
        for acl in acls:
            LOG.info("\nacl: %s" % (acl))
            match_obj = re.match(ACL_REGEX, acl.text)
            segment_id = match_obj.group(1)
            segment_id = int(segment_id)
            LOG.info("   segment_id: %s" % (segment_id))
            
            # Check that segment_id exists in openstack DB info
            if segment_id not in intf_segment_dict:
                LOG.info("Segment ID not found, deleting acl")
                delete_acl_list.append(acl.text)

            # Check that permit rules match subnets defined on openstack intfs
            if self.check_acl_permit_rules_valid(segment_id, acl, intf_segment_dict) is False:
                delete_acl_list.append(acl.text)

            
        for acl_cfg in delete_acl_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (acl_cfg))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            

    def clean_interfaces(self, conn, intf_segment_dict, segment_nat_dict, parsed_cfg):
        
        runcfg_intfs = [obj for obj in parsed_cfg.find_objects("^interf") \
                        if obj.re_search_children("description OPENSTACK_NEUTRON_INTF")]

        LOG.info("intf_segment_dict: %s" % (intf_segment_dict))
        pending_delete_list = []

        # TODO: split this big function into smaller functions
        for intf in runcfg_intfs:
            LOG.info("\nOpenstack interface: %s" % (intf))
            intf.intf_num = int(intf.re_match(INTF_REGEX, group=1))
            intf.segment_id = int(intf.re_match(INTF_REGEX, group=2))
            LOG.info("  num: %s  segment_id: %s" % (intf.intf_num, intf.segment_id))

            # Delete any interfaces where config doesn't match DB
            # Correct config will be added after clearing invalid cfg

            # TODO: Check that interface name (e.g. Port-channel10) matches that
            #       specified in .ini file

            # Check that the interface segment_id exists in the current DB data
            if intf.segment_id not in intf_segment_dict:
                LOG.info("Invalid segment ID, delete interface")
                pending_delete_list.append(intf)
                continue

            # Check if dot1q config is correct
            dot1q_cfg = intf.re_search_children(DOT1Q_REGEX)
            dot1q_cfg = self.get_single_cfg(dot1q_cfg)

            if dot1q_cfg is None:
                LOG.info("Missing DOT1Q config, delete interface")
                pending_delete_list.append(intf)
                continue
            else:
                dot1q_num = int(dot1q_cfg.re_match(DOT1Q_REGEX, group=1))
                if dot1q_num != intf.segment_id:
                    LOG.info("DOT1Q mismatch, delete interface")
                    pending_delete_list.append(intf)
                    continue

            # Is this an "external network" segment_id?
            db_intf = intf_segment_dict[intf.segment_id][0]
            intf_type = db_intf["device_owner"]
            intf.is_external = (intf_type == constants.DEVICE_OWNER_ROUTER_HA_GW or \
                                intf_type == constants.DEVICE_OWNER_ROUTER_GW)
            
            # Check VRF config
            if intf.is_external:
                vrf_cfg = intf.re_search_children(VRF_EXT_INTF_REGEX)
                vrf_cfg = self.get_single_cfg(vrf_cfg)
                LOG.info("VRF: %s" % (vrf_cfg))
                if vrf_cfg is not None: # external network has no vrf
                    LOG.info("External network shouldn't have VRF, deleting intf")
                    pending_delete_list.append(intf)
                    continue
            else:
                vrf_cfg = intf.re_search_children(VRF_INTF_REGEX)
                vrf_cfg = self.get_single_cfg(vrf_cfg)
                LOG.info("VRF: %s" % (vrf_cfg))
                if not vrf_cfg:
                    LOG.info("Internal network missing valid VRF, deleting intf")
                    pending_delete_list.append(intf)
                    continue
                
                # check for VRF mismatch
                router_id = vrf_cfg.re_match(VRF_INTF_REGEX, group=1)
                if router_id != db_intf["device_id"][0:6]:
                    LOG.info("Internal network VRF mismatch, deleting intf")
                    pending_delete_list.append(intf)
                    continue

            # Checks beyond this point don't trigger intf delete

            # Fix NAT config
            intf_nat_type = intf.re_search_children(INTF_NAT_REGEX)
            intf_nat_type = self.get_single_cfg(intf_nat_type)

            if intf_nat_type is not None:
                intf_nat_type = intf_nat_type.re_match(INTF_NAT_REGEX, group=1)
            
            LOG.info("NAT Type: %s" % intf_nat_type)

            if segment_nat_dict[intf.segment_id] == True:
                if intf.is_external:
                    if intf_nat_type != "outside":
                        nat_cmd = XML_CMD_TAG % (intf.text)
                        nat_cmd += XML_CMD_TAG % ("ip nat outside")
                        confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                        LOG.info("NAT type mismatch, should be outside")
                        rpc_obj = conn.edit_config(target='running', config=confstr)
                else:
                    if intf_nat_type != "inside":
                        nat_cmd = XML_CMD_TAG % (intf.text)
                        nat_cmd += XML_CMD_TAG % ("ip nat inside")
                        confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                        LOG.info("NAT type mismatch, should be inside")
                        rpc_obj = conn.edit_config(target='running', config=confstr)
            else:
                if intf_nat_type is not None:
                    nat_cmd = XML_CMD_TAG % (intf.text)
                    nat_cmd += XML_CMD_TAG % ("no ip nat %s" % (intf_nat_type))
                    confstr = XML_FREEFORM_SNIPPET % (nat_cmd)
                    LOG.info("NAT type mismatch, should have no NAT")
                    rpc_obj = conn.edit_config(target='running', config=confstr)

            
            # Delete any hsrp config with wrong group number
            del_hsrp_cmd = XML_CMD_TAG % (intf.text)
            hsrp_cfg_list = intf.re_search_children(HSRP_REGEX)
            needs_hsrp_delete = False
            for hsrp_cfg in hsrp_cfg_list:
                hsrp_num = int(hsrp_cfg.re_match(HSRP_REGEX, group=1))
                if hsrp_num != intf.segment_id:
                    needs_hsrp_delete = True
                    del_hsrp_cmd += XML_CMD_TAG % ("no %s" % (hsrp_cfg.text))
            
            if needs_hsrp_delete:
                confstr = XML_FREEFORM_SNIPPET % (del_hsrp_cmd)
                LOG.info("Deleting bad HSRP config: %s" % (confstr))
                rpc_obj = conn.edit_config(target='running', config=confstr)
                
        for intf in pending_delete_list:
            del_cmd = XML_CMD_TAG % ("no %s" % (intf.text))
            confstr = XML_FREEFORM_SNIPPET % (del_cmd)
            LOG.info("Deleting %s" % (intf.text))
            LOG.info(confstr)
            rpc_obj = conn.edit_config(target='running', config=confstr)


