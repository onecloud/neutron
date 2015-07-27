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
