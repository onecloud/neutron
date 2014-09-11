## cisco plugin icehouse backport notes ##

1.)
Define keystone_authtoken.identity_uri in neutron.conf. This is needed by a db module in the cisco plugin.

[keystone_authtoken]
auth_host = 127.0.0.1
auth_port = 35357
...
identity_uri=http://127.0.0.1:35357

2.)

Set CiscoRouterPlugin as a service plugin:

service_plugins = neutron.plugins.cisco.service_plugins.cisco_router_plugin.CiscoRouterPlugin,neutron.services.firewall.fwaas_plugin.FirewallPlugin



----------------------------------
# -- Welcome!

  You have come across a cloud computing network fabric controller.  It has
  identified itself as "Neutron."  It aims to tame your (cloud) networking!

# -- External Resources:

 The homepage for Neutron is: http://launchpad.net/neutron .  Use this
 site for asking for help, and filing bugs. Code is available on github at
 <http://github.com/openstack/neutron>.

 The latest and most in-depth documentation on how to use Neutron is
 available at: <http://docs.openstack.org>.  This includes:

 Neutron Administrator Guide
 http://docs.openstack.org/trunk/openstack-network/admin/content/

 Neutron API Reference:
 http://docs.openstack.org/api/openstack-network/2.0/content/

 The start of some developer documentation is available at:
 http://wiki.openstack.org/NeutronDevelopment

 For help using or hacking on Neutron, you can send mail to
 <mailto:openstack-dev@lists.openstack.org>.
