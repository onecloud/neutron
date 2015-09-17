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

test_config_sample1 = ['!',
                       '! Last configuration change at 23:12:27 UTC ',
                       'Sat Jul 25 2015 by kahou', '!', 'version 15.5',
                       'service timestamps debug datetime msec',
                       'service timestamps log datetime msec',
                       'no platform punt-keepalive disable-kernel-core',
                       'platform console auto',
                       '!',
                       'hostname R1',
                       '!',
                       'boot-start-marker',
                       'boot-end-marker',
                       '!',
                       '!',
                       'vrf definition nrouter-PHYSIC-qqq',
                       ' !',
                       ' address-family ipv4',
                       ' exit-address-family',
                       ' !',
                       ' address-family ipv6',
                       ' exit-address-family',
                       '!',
                       'vrf definition nrouter-dec967-qqq',
                       ' !',
                       ' address-family ipv4',
                       ' exit-address-family',
                       ' !',
                       ' address-family ipv6',
                       ' exit-address-family',
                       '!',
                       '!',
                       'no aaa new-model',
                       '!', '!', '!', '!', '!', '!', '!', '!', '!',
                       'ip domain name demo.net',
                       '!', '!', '!', '!', '!', '!', '!', '!', '!', '!',
                       'subscriber templating',
                       '!',
                       'multilink bundle-name authenticated',
                       '!', '!', '!',
                       'license udi pid CSR1000V sn 9AR00EWCYM8',
                       'spanning-tree extend system-id', '!',
                       'username kahou privilege 15 secret 5 '
                       '$1$m0nW$ANG7q3x9jVWDhWVesc7KM/',
                       '!', 'redundancy', '!', '!', '!', '!', '!', '!',
                       'ip ssh version 2', '! ', '!', '!', '!',
                       '!', '!', '!', '!', '!',
                       '!', '!', '!', '!', '! ', '! ', '!',
                       'interface GigabitEthernet1',
                       ' ip address 192.168.58.111 255.255.255.0',
                       ' negotiation auto', '!', 'interface GigabitEthernet2',
                       ' ip address 192.168.60.111 255.255.255.0',
                       ' negotiation auto', '!',
                       'interface GigabitEthernet2.1001',
                       ' description OPENSTACK_NEUTRON-qqq_INTF',
                       ' encapsulation dot1Q 1001',
                       ' vrf forwarding nrouter-dec967-qqq',
                       ' ip address 60.0.0.8 255.255.255.0',
                       ' ip nat inside',
                       ' standby delay minimum 30 reload 60',
                       ' standby version 2',
                       ' standby 1064 ip 60.0.0.1', ' standby 1064 timers 1 3',
                       ' standby 1064 priority 0', '!',
                       'interface GigabitEthernet3',
                       ' ip address 192.168.62.111 255.255.255.0',
                       ' negotiation auto', '!',
                       'interface GigabitEthernet3.1000',
                       ' description OPENSTACK_NEUTRON-qqq_INTF',
                       ' encapsulation dot1Q 1000',
                       ' ip address 31.0.0.5 255.255.255.0',
                       ' ip nat outside',
                       ' standby delay minimum 30 reload 60',
                       ' standby version 2', ' standby 1064 ip 31.0.0.4',
                       ' standby 1064 timers 1 3',
                       ' standby 1064 priority 0',
                       ' standby 1064 name neutron-hsrp-grp-1064-100', '!',
                       '!',
                       'virtual-service csr_mgmt', '!',
                       'ip nat pool nrouter-dec967-qqq_nat_pool '
                       '31.0.0.3 31.0.0.3 '
                       'netmask 255.255.255.0',
                       'ip nat inside source list neutron_acl_qqq_1001 pool '
                       'nrouter-dec967-qqq_nat_pool vrf '
                       'nrouter-dec967-qqq overload',
                       'ip forward-protocol nd', '!',
                       'no ip http server',
                       'no ip http secure-server',
                       'ip route vrf nrouter-dec967-qqq 0.0.0.0 0.0.0.0 '
                       'GigabitEthernet3.1000 31.0.0.1', '!',
                       'ip access-list standard neutron_acl_qqq_1001',
                       ' permit 60.0.0.0 0.0.0.255', '!', '!', '!', '!',
                       'control-plane', '!', '!', 'line con 0',
                       ' stopbits 1',
                       'line vty 0 4', ' login local',
                       ' transport preferred none',
                       ' transport input ssh', '!', 'netconf max-sessions 5',
                       'netconf lock-time 60', 'netconf max-message 37283',
                       'netconf ssh acl 1', '!', 'end', '']

routers_data_1 = [
    {
        'status': 'ACTIVE',
        'external_gateway_info': {
            'network_id': '12',
            'external_fixed_ips': [
                {
                    'subnet_id': '13',
                    'ip_address': '172.0.0.6'
                }]
        },
        'name': 'router',
        'gw_port_id': 'f05e632a-f692-4202-94f7-84975a538162',
        'admin_state_up': True,
        'routes': [],
        'tenant_id': '14ccac93872c455ebd62a36772ba770b',
        'gw_port': {
            'status': 'ACTIVE',
            'binding:host_id': 'base',
            'allowed_address_pairs': [],
            'extra_dhcp_opts': [],
            'device_owner': 'network:router_gateway',
            'binding:profile': {},
            'fixed_ips': [
                {
                    'subnet_id': '13',
                    'ip_address': '172.0.0.6'
                }],
            'id': '99',
            'security_groups': [],
            'device_id': '88',
            'subnet': {
                'ipv6_ra_mode': None,
                'cidr': '172.0.0.0/24',
                'gateway_ip': '172.0.0.1',
                'id': '12'
            },
            'name': '',
            'admin_state_up': True,
            'network_id': '13',
            'tenant_id': '',
            'binding:vif_details': {
                'port_filter': True
            },
            'binding:vnic_type': 'normal',
            'binding:vif_type': 'bridge',
            'mac_address': 'fa:16:3e:32:9a:d9',
            'extra_subnets': []
        },
        'id': '999'
    },
    {
        'status': 'ACTIVE',
        'external_gateway_info': None,
        'name': 'PHYSICAL_GLOBAL_ROUTER_ID',
        'gw_port_id': None,
        'admin_state_up': True,
        'routes': [],
        'tenant_id': '',
        'id': 'PHYSICAL_GLOBAL_ROUTER_ID'
    }
]

floating_ips_1 = [
    {
        'floating_network_id': '12',
        'router_id': '999',
        'fixed_ip_address': '20.0.0.5',
        'floating_ip_address': '172.0.0.9',
        'floating_port_id': '11',
        'tenant_id': '99',
        'status': 'ACTIVE',
        'port_id': '88',
        'id': '123'
    }
]

interfaces_1 = [
    {
        'status': 'ACTIVE',
        'binding:host_id': 'base',
        'allowed_address_pairs': [],
        'extra_dhcp_opts': [],
        'device_owner': 'network:router_interface',
        'binding:profile': {},
        'fixed_ips': [
            {
                'subnet_id': 'db',
                'ip_address': '10.0.0.1'
            }
        ],
        'id': '113dd29f-76e2-4bd9-b0e2-5bc1d95ac83c',
        'security_groups': [],
        'device_id': '999',
        'subnet': {
            'ipv6_ra_mode': None,
            'cidr': '10.0.0.0/24',
            'gateway_ip': '10.0.0.1',
            'id': 'dba6c8e4-eaef-4e34-a093-b4bcee8fd64e'
        },
        'name': '',
        'admin_state_up': True,
        'network_id': 'a2135915-f8cf-4072-b84c-9f51fef2760f',
        'tenant_id': '14ccac93872c455ebd62a36772ba770b',
        'binding:vif_details':
        {
            'port_filter': True
        },
        'binding:vnic_type': 'normal',
        'binding:vif_type': 'bridge',
        'mac_address': 'fa:16:3e:4b:c7:0f',
        'extra_subnets': []
    },
    {
        'status': 'ACTIVE',
        'binding:host_id': 'base',
        'allowed_address_pairs': [],
        'extra_dhcp_opts': [],
        'device_owner': 'network:router_interface',
        'binding:profile': {},
        'fixed_ips': [
            {
                'subnet_id': '42f',
                'ip_address': '20.0.0.1'
            }
        ],
        'id': 'f502e8a4-10a2-4da7-8972-3e04f2dff8ec',
        'security_groups': [],
        'device_id': '999',
        'subnet': {
            'ipv6_ra_mode': None,
            'cidr': '20.0.0.0/24',
            'gateway_ip': '20.0.0.1',
            'id': '42ff3c6e-b20d-48ee-ae8b-379be8dee2e1'
        },
        'name': '',
        'admin_state_up': True,
        'network_id': '8980f01b-6826-40dc-9ac9-782c5db77b93',
        'tenant_id': '14ccac93872c455ebd62a36772ba770b',
        'binding:vif_details': {
            'port_filter': True
        },
        'binding:vnic_type': 'normal',
        'binding:vif_type': 'bridge',
        'mac_address': 'fa:16:3e:a8:15:e8',
        'extra_subnets': []
    },
    {
        'status': 'ACTIVE',
        'binding:host_id': 'base',
        'phy_router_db': "123",
        'allowed_address_pairs': [],
        'extra_dhcp_opts': [],
        'device_owner': 'network:router_ha_interface',
        'port_binding_db': "123",
        'binding:profile': {},
        'fixed_ips': [
            {
                'subnet_id': '42ff3c6e-b20d-48ee-ae8b-379be8dee2e1',
                'ip_address': '20.0.0.4'
            }
        ],
        'id': '5fdc5e77-a72c-4447-8ff2-41c19a6eeced',
        'security_groups': [],
        'device_id': '999',
        'subnet': {
            'ipv6_ra_mode': None,
            'cidr': '20.0.0.0/24',
            'gateway_ip': u'20.0.0.1',
            'id': '42ff3c6e-b20d-48ee-ae8b-379be8dee2e1'
        },
        'name': '',
        'admin_state_up': True,
        'network_id': '8980f01b-6826-40dc-9ac9-782c5db77b93',
        'tenant_id': '',
        'binding:vif_details': {
            'port_filter': True
        },
        'binding:vnic_type': 'normal',
        'binding:vif_type': 'bridge',
        'mac_address': 'fa:16:3e:d7:75:16',
        'extra_subnets': []
    },
    {
        'status': 'ACTIVE',
        'binding:host_id': 'base',
        'phy_router_db': "123",
        'allowed_address_pairs': [],
        'extra_dhcp_opts': [],
        'device_owner': 'network:router_ha_interface',
        'port_binding_db': "1234",
        'binding:profile': {},
        'fixed_ips': [
            {
                'subnet_id': 'dba',
                'ip_address': '10.0.0.4'
            }
        ],
        'id': 'a49a5a08-8f6f-44be-b577-108cbb26b1fd',
        'security_groups': [],
        'device_id': '59372c25-b4e1-424d-bfa5-d14f4cb012ef',
        'subnet': {
            'ipv6_ra_mode': None,
            'cidr': '10.0.0.0/24',
            'gateway_ip': '10.0.0.1',
            'id': 'dba6c8e4-eaef-4e34-a093-b4bcee8fd64e'
        },
        'name': '',
        'admin_state_up': True,
        'network_id': 'a2135915-f8cf-4072-b84c-9f51fef2760f',
        'tenant_id': '',
        'binding:vif_details': {
            'port_filter': True
        },
        'binding:vnic_type': 'normal',
        'binding:vif_type': 'bridge',
        'mac_address': 'fa:16:3e:db:0e:22',
        'extra_subnets': []
    }
]

sub_if_1 = ['!', 'interface GigabitEthernet2.1001',
            ' description OPENSTACK_NEUTRON-qqq_INTF',
            ' encapsulation dot1Q 1001',
            ' vrf forwarding nrouter-dec967-qqq',
            ' ip address 60.0.0.8 255.255.255.0',
            ' ip nat inside',
            ' redundancy rii 1001',
            ' redundancy group 1 ip 60.0.0.1 exclusive decrement 10']

sub_ex_if_1 = ['!', 'interface GigabitEthernet2.1000',
               ' description OPENSTACK_NEUTRON-qqq_INTF',
               ' encapsulation dot1Q 1000',
               ' ip address 31.0.0.5 255.255.255.0',
               ' ip nat outside',
               ' redundancy rii 1000',
               ' redundancy group 1 ip 31.0.0.1 exclusive decrement 10']

# Mismatch vlan ID and rii value
wrong_sub_if_1 = ['!', 'interface GigabitEthernet2.1001',
                  ' description OPENSTACK_NEUTRON-qqq_INTF',
                  ' encapsulation dot1Q 1001',
                  ' vrf forwarding nrouter-dec967-qqq',
                  ' ip address 60.0.0.8 255.255.255.0',
                  ' ip nat inside',
                  ' redundancy rii 1002',
                  ' redundancy group 1 ip 60.0.0.1 exclusive decrement 10']
