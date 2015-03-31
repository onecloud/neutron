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
# @author: Hareesh Puthalath, Cisco Systems, Inc.

"""
CSR (IOS-XE) XML-based configuration snippets
"""

# The standard Template used to interact with IOS-XE(CSR).
# This template is added by the netconf client
# EXEC_CONF_SNIPPET = """
#       <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
#         <configure>
#           <__XML__MODE__exec_configure>%s
#           </__XML__MODE__exec_configure>
#         </configure>
#       </config>
# """


#=================================================#
# Set ip address on an interface
# $(config)interface GigabitEthernet 1
# $(config)ip address 10.0.100.1 255.255.255.0
#=================================================#
SET_INTC = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Enable an interface
# $(config)interface GigabitEthernet 1
# $(config)no shutdown
#=================================================#
ENABLE_INTF = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no shutdown</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create VRF
# $(config)ip routing
# $(config)ip vrf nrouter-e7d4y5
#=================================================#
CREATE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove VRF
# $(config)ip routing
# $(config)no ip vrf nrouter-e7d4y5
#=================================================#
REMOVE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>no ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)ip address 192.168.0.1 255.255.255.0
#=================================================#
CREATE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>ip vrf forwarding %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Create Subinterface (with deployment_id)
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)vrf forwarding nrouter-abc-e7d4y5
# $(config)ip address 192.168.0.1 255.255.255.0
#=================================================#
CREATE_SUBINTERFACE_WITH_ID = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>description OPENSTACK_NEUTRON-%s_INTF</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>vrf forwarding %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create Subinterface (External. no VRF)
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)ip address 192.168.0.1 255.255.255.0
#=================================================#
CREATE_SUBINTERFACE_EXTERNAL_WITH_ID = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>description OPENSTACK_NEUTRON-%s_INTF</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>

"""


#=================================================#
# Remove Subinterface
# $(config)no interface GigabitEthernet 2.500
#=================================================#
REMOVE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>no interface %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Enable HSRP on a Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)standby version 2
# $(config)standby <group> priority <priority>
# $(config)standby <group> ip <ip>
#=================================================#
SET_INTC_HSRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip vrf forwarding %s</cmd>
            <cmd>standby version 2</cmd>
            <cmd>standby %s priority %s</cmd>
            <cmd>standby %s ip %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Enable HSRP on a Subinterface for ASR 
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)standby version 2
# $(config)standby <group> priority <priority>
# $(config)standby <group> ip <ip>
#=================================================#
SET_INTC_ASR_HSRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>vrf forwarding %s</cmd>
            <cmd>standby version 2</cmd>
            <cmd>standby delay minimum 30 reload 60</cmd>
            <cmd>standby %s priority %s</cmd>
            <cmd>standby %s ip %s</cmd>
            <cmd>standby %s timers 3 10</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Enable VRRP on a Subinterface for ASR 
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)vrrp delay minimum 30 reload 60
# $(config)vrrp <group> priority <priority>
# $(config)vrrp <group> ip <ip>
#=================================================#
SET_INTC_ASR_VRRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>vrf forwarding %s</cmd>
            <cmd>vrrp delay minimum 30 reload 60</cmd>
            <cmd>vrrp %s priority %s</cmd>
            <cmd>vrrp %s ip %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Enable RG on a Subinterface for ASR 
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)redundancy rii <rii: use vlan as rii>
# $(config)redundancy group <group-number> ip <ip>
#=================================================#
SET_INTC_ASR_RG = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>vrf forwarding %s</cmd>
            <cmd>redundancy rii %s</cmd>
            <cmd>redundancy group %s ip %s exclusive</cmd>
        </cli-config-data>
</config>

"""


#            <cmd>standby %s name neutron-hsrp-grp-%s</cmd>
#            <cmd>standby %s preempt</cmd>


#=================================================#
# Enable HSRP on a External Network Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)standby version 2
# $(config)standby <group> priority <priority>
# $(config)standby <group> ip <ip>
#=================================================#
SET_INTC_ASR_HSRP_EXTERNAL = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>standby version 2</cmd>
            <cmd>standby delay minimum 30 reload 60</cmd>
            <cmd>standby %s priority %s</cmd>
            <cmd>standby %s ip %s</cmd>
            <cmd>standby %s timers 3 10</cmd>
            <cmd>standby %s name neutron-hsrp-grp-%s-%s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Enable VRRP on a External Network Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)redundancy rii <rii>
# $(config)redundancy group <redundancy group> ip <ip> exclusive
#=================================================#
SET_INTC_ASR_RG_EXTERNAL = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>redundancy rii %s</cmd>
            <cmd>redundancy group %s ip %s exclusive</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Enable VRRP on a External Network Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)vrrp delay minimum 30 reload 60
# $(config)vrrp <group> priority <priority>
# $(config)vrrp <group> ip <ip>
# $(config)vrrp <group> name neutron-hsrp-grp-<group>-<vlan></cmd>
#=================================================#
SET_INTC_ASR_VRRP_EXTERNAL = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>vrrp delay minimum 30 reload 60</cmd>
            <cmd>vrrp %s priority %s</cmd>
            <cmd>vrrp %s ip %s</cmd>
            <cmd>vrrp %s name neutron-hsrp-grp-%s-%s</cmd>
        </cli-config-data>
</config>

"""

#             <cmd>standby %s preempt</cmd>


#=================================================#
# Remove HSRP on a Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)no standby version 2
# $(config)no standby <group>
#=================================================#
REMOVE_INTC_HSRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no standby %s</cmd>
            <cmd>no standby version 2</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Remove VRRP on a Subinterface
# $(config)interface GigabitEthernet 2.500
# $(config)no standby version 2
# $(config)no standby <group>
#=================================================#
REMOVE_INTC_VRRP = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no vrrp %s</cmd>
        </cli-config-data>
</config>

"""


#=================================================#
# Create Access Control List
# $(config)ip access-list standard acl_500
# $(config)permit 192.168.0.1 255.255.255.0
#=================================================#
CREATE_ACL = """
<config>
        <cli-config-data>
            <cmd>ip access-list standard %s</cmd>
            <cmd>permit %s %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove Access Control List
# $(config)no ip access-list standard acl_500
#=================================================#
REMOVE_ACL = """
<config>
        <cli-config-data>
            <cmd>no ip access-list standard %s</cmd>
        </cli-config-data>
</config>
"""

#=========================================================================#
# Set Dynamic source translation on an interface
# Syntax: ip nat inside source list <acl_no> interface <interface>
# .......vrf <vrf_name> overload
# eg: $(config)ip nat inside source list acl_500
#    ..........interface GigabitEthernet3.100 vrf nrouter-e7d4y5 overload
#========================================================================#
SNAT_CFG = "ip nat inside source list %s interface %s vrf %s overload"

SET_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source list %s interface %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Dynamic source translation on an interface
# Syntax: no ip nat inside source list <acl_no> interface <interface>
# .......vrf <vrf_name> overload
# eg: $(config)no ip nat inside source list acl_500
#    ..........interface GigabitEthernet3.100 vrf nrouter-e7d4y5 overload
#========================================================================#
REMOVE_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source list %s interface %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Set NAT
# Syntax : interface <interface>
#          ip nat <inside|outside>
#=================================================#
SET_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip nat %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Remove NAT
# Syntax : interface <interface>
#          no ip nat <inside|outside>
#=================================================#
REMOVE_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no ip nat %s</cmd>
        </cli-config-data>
</config>
"""

#=========================================================================#
# Set Static source translation on an interface
# Syntax: ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> match-in-vrf
# eg: $(config)ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 match-in-vrf
#========================================================================#
SET_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source static %s %s vrf %s match-in-vrf</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Static source translation on an interface
# Syntax: no ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> match-in-vrf
# eg: $(config)no ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 match-in-vrf
#========================================================================#
REMOVE_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source static %s %s vrf %s match-in-vrf</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Set Static source translation on an interface
# Syntax: ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> redundancy <hsrp group name> 
# eg: $(config)ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 redundancy neutron-hsrp-grp-305 
#========================================================================#
SET_STATIC_SRC_TRL_NO_VRF_MATCH = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source static %s %s vrf %s redundancy neutron-hsrp-grp-%s-%s</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Static source translation on an interface
# Syntax: no ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> redundancy <hsrp group name> 
# eg: $(config)no ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 redundancy neutron-hsrp-grp-305
#========================================================================#
REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source static %s %s vrf %s redundancy neutron-hsrp-grp-%s-%s</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Set Static source translation on an interface
# Syntax: ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> redundancy <hsrp group name> 
# eg: $(config)ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 redundancy 1 mapping-id 10000 
#========================================================================#
SET_STATIC_SRC_TRL_NO_VRF_MATCH_RG = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source static %s %s vrf %s redundancy %s mapping-id %s</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Static source translation on an interface
# Syntax: no ip nat inside source static <fixed_ip> <floating_ip>
# .......vrf <vrf_name> redundancy <hsrp group name> 
# eg: $(config)no ip nat inside source static 192.168.0.1 121.158.0.5
#    ..........vrf nrouter-e7d4y5 redundancy 1 mapping-id 10000 
#========================================================================#
REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH_RG = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source static %s %s vrf %s redundancy %s mapping-id %s</cmd>
        </cli-config-data>
</config>

"""


#=============================================================================#
# Set ip route
# Syntax: ip route vrf <vrf-name> <destination> <mask> [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 8.8.0.0  255.255.0.0 10.0.100.255
#=============================================================================#
SET_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove ip route
# Syntax: no ip route vrf <vrf-name> <destination> <mask>
#        [<interface>] <next hop>
# eg: $(config)no ip route vrf nrouter-e7d4y5 8.8.0.0  255.255.0.0 10.0.100.255
#=============================================================================#
REMOVE_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""
#=============================================================================#
# Set default ip route
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0  0.0.0.0 10.0.100.255
#=============================================================================#
DEFAULT_ROUTE_CFG = 'ip route vrf %s 0.0.0.0 0.0.0.0 %s'

SET_DEFAULT_ROUTE = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s 0.0.0.0 0.0.0.0 %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove default ip route
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 [<interface>] <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0  0.0.0.0 10.0.100.255
#=============================================================================#
REMOVE_DEFAULT_ROUTE = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s 0.0.0.0 0.0.0.0 %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Set default ip route with interface
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 <interface> <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0  0.0.0.0 po10.304 10.0.100.255
#=============================================================================#
DEFAULT_ROUTE_WITH_INTF_CFG = 'ip route vrf %s 0.0.0.0 0.0.0.0 %s %s'

SET_DEFAULT_ROUTE_WITH_INTF = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s 0.0.0.0 0.0.0.0 %s %s</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove default ip route
# Syntax: ip route vrf <vrf-name> 0.0.0.0 0.0.0.0 <interface> <next hop>
# eg: $(config)ip route vrf nrouter-e7d4y5 0.0.0.0 0.0.0.0 po10.304 10.0.100.255
#=============================================================================#
REMOVE_DEFAULT_ROUTE_WITH_INTF = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s 0.0.0.0 0.0.0.0 %s %s</cmd>
        </cli-config-data>
</config>
"""


#=============================================================================#
# Clear dynamic nat translations. This is used to clear any nat bindings before
# we can turn off NAT on an interface
# Syntax: clear ip nat translation [forced]
#=============================================================================#
# CLEAR_DYN_NAT_TRANS = """
# <oper-data-format-text-block>
#     <exec>clear ip nat translation forced</exec>
# </oper-data-format-text-block>
# """
CLEAR_DYN_NAT_TRANS = """
<config>
        <cli-config-data>
            <cmd>do clear ip nat translation forced</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Empty snippet (for polling netconf session status)
#=================================================#
EMPTY_SNIPPET = """
<config>
        <cli-config-data>
            <cmd>do cd</cmd>
        </cli-config-data>
</config>
"""



#=================================================#
# Create VRF definition
# $(config)vrf definition nrouter-e7d4y5
#=================================================#
CREATE_VRF_DEFN = """
<config>
        <cli-config-data>
            <cmd>vrf definition %s</cmd>
            <cmd>address-family ipv4</cmd>
            <cmd>exit-address-family</cmd>
            <cmd>address-family ipv6</cmd>
            <cmd>exit-address-family</cmd>
        </cli-config-data>
</config>
"""
#            <cmd>rd %s:%s</cmd>

#=================================================#
# Remove VRF definition
# $(config)no vrf definition nrouter-e7d4y5
#=================================================#
REMOVE_VRF_DEFN = """
<config>
        <cli-config-data>
            <cmd>no vrf definition %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create Subinterface (with deployment_id)
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)vrf forwarding nrouter-abc-e7d4y5
# $(config)ip address 2001:DB8:CAFE:A::1/64
#=================================================#
CREATE_SUBINTERFACE_V6_WITH_ID = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>description OPENSTACK_NEUTRON-%s_INTF</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>vrf forwarding %s</cmd>
            <cmd>ipv6 address %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Create Subinterface (with deployment_id)
# $(config)interface GigabitEthernet 2.500
# $(config)encapsulation dot1Q 500
# $(config)vrf forwarding nrouter-abc-e7d4y5
# $(config)ip address 2001:DB8:CAFE:A::1/64
#=================================================#
CREATE_SUBINTERFACE_V6_NO_VRF_WITH_ID = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>description OPENSTACK_NEUTRON-%s_INTF</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>ipv6 address %s</cmd>
        </cli-config-data>
</config>
"""

#=================================================#
# Enable HSRP on a Subinterface for ASR 
# $(config)interface GigabitEthernet 2.500
# $(config)vrf forwarding nrouter-e7d4y5
# $(config)standby version 2
# $(config)standby <group> priority <priority>
# $(config)standby <group> ip <ip>
#=================================================#
SET_INTC_ASR_HSRP_V6 = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>standby version 2</cmd>
            <cmd>standby %s ipv6 autoconfig</cmd>
            <cmd>standby %s priority %s</cmd>
            <cmd>standby %s preempt</cmd>
            <cmd>standby %s authentication OPEN</cmd>
            <cmd>standby %s timers 3 10</cmd>
            <cmd>standby %s name neutron-hsrp-grp-%s</cmd>
        </cli-config-data>
</config>
"""



#=============================================================================#
# Set default ipv6 route with interface
# Syntax: ipv6 route vrf <vrf-name> ::/0 <interface> <next hop>
# eg: $(config)ipv6 route vrf nrouter-e7d4y5 ::/0 po10.304 2001:DB8:CAFE:22::1/64
#=============================================================================#
DEFAULT_ROUTE_V6_WITH_INTF_CFG = 'ipv6 route vrf %s ::/0 %s %s'

SET_DEFAULT_ROUTE_V6_WITH_INTF = """
<config>
        <cli-config-data>
            <cmd>ipv6 route vrf %s ::/0 %s nexthop-vrf default</cmd>
        </cli-config-data>
</config>
"""

#=============================================================================#
# Remove default ipv6 route
# Syntax: ipv6 route vrf <vrf-name> ::/0 <interface> <next hop>
# eg: $(config)ipv6 route vrf nrouter-e7d4y5 ::/0 po10.304 2001:DB8:CAFE:22::1/64
#=============================================================================#
REMOVE_DEFAULT_ROUTE_V6_WITH_INTF = """
<config>
        <cli-config-data>
            <cmd>no ipv6 route vrf %s ::/0 %s nexthop-vrf default</cmd>
        </cli-config-data>
</config>
"""

#=========================================================================#
# Set Dynamic source translation with NAT pool
# Syntax: ip nat inside source list <acl_no> pool <pool_name>
# .......vrf <vrf_name> overload
# eg: $(config)ip nat inside source list acl_500
#    ..........pool nrouter-e7d4y5-pool vrf nrouter-e7d4y5 overload
#========================================================================#
SNAT_POOL_CFG = "ip nat inside source list %s pool %s vrf %s overload"

SET_DYN_SRC_TRL_POOL = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source list %s pool %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Remove Dynamic source translation with NAT pool
# Syntax: no ip nat inside source list <acl_no> pool <pool_name>
# .......vrf <vrf_name> overload
# eg: $(config)no ip nat inside source list acl_500
#    ..........pool nrouter-e7d4y5-pool vrf nrouter-e7d4y5 overload
#========================================================================#
REMOVE_DYN_SRC_TRL_POOL = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source list %s pool %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Create a NAT pool
# Syntax: ip nat pool <pool_name> <start_ip> <end_ip> netmask <netmask_value>
# eg: $(config)ip nat pool TEST_POOL 192.168.0.20 192.168.0.35 netmask 255.255.0.0
#========================================================================#
CREATE_NAT_POOL = """
<config>
        <cli-config-data>
            <cmd>ip nat pool %s %s %s netmask %s</cmd>
        </cli-config-data>
</config>

"""

#=========================================================================#
# Delete a NAT pool
# Syntax: no ip nat pool <pool_name> <start_ip> <end_ip> netmask <netmask_value>
# eg: $(config)no ip nat pool TEST_POOL 192.168.0.20 192.168.0.35 netmask 255.255.0.0
#========================================================================#
DELETE_NAT_POOL = """
<config>
        <cli-config-data>
            <cmd>no ip nat pool %s %s %s netmask %s</cmd>
        </cli-config-data>
</config>

"""

#=================================================#
# Disable HSRP preempt on an interface
#=================================================#
REMOVE_INTC_ASR_HSRP_PREEMPT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no standby %s preempt</cmd>
        </cli-config-data>
</config>

"""

GET_SHOW_CLOCK = """
<filter type="subtree">
    <config-format-text-cmd>
        <text-filter-spec> | inc FFFFFFFFFFFFFFFF</text-filter-spec>
    </config-format-text-cmd>    
    <oper-data-format-text-block>
        <exec>show clock</exec>
    </oper-data-format-text-block>
</filter>
"""
