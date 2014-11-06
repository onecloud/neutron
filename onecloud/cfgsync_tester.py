import re
import xml.etree.ElementTree as ET

from ncclient import manager as nc_manager
import ciscoconfparse
import sys

from neutron import manager
from neutron.agent.common import config
from neutron.common import rpc as n_rpc
from neutron.openstack.common.rpc import proxy  # ICEHOUSE_BACKPORT
from neutron import context as n_context
from oslo.config import cfg
from neutron.common import config as common_config
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.openstack.common import loopingcall


class CiscoRoutingPluginApi(proxy.RpcProxy):
    """RoutingServiceHelper(Agent) side of the  routing RPC API."""

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic, host):
        super(CiscoRoutingPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def register(self, context):
        self.call(context,
                  self.make_msg('register_for_duty',
                                host=self.host),
                  topic=self.topic)

    def get_routers(self, context, router_ids=None, hd_ids=None):
        """Make a remote process call to retrieve the sync data for routers.

        :param context: session context
        :param router_ids: list of  routers to fetch
        :param hd_ids : hosting device ids, only routers assigned to these
                        hosting devices will be returned.
        """
        return self.call(context,
                         self.make_msg('sync_routers',
                                       host=self.host,
                                       router_ids=router_ids,
                                       hosting_device_ids=hd_ids),
                         topic=self.topic)

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])


class ConfigSyncTester(manager.Manager):

    def __init__(self):
        self.plugin_rpc = CiscoRoutingPluginApi("q-l3-plugin", "localhost.localdomain")
        self.context = n_context.get_admin_context_without_session()
        
        self.plugin_rpc.register(self.context)
        self.start_test_loop(self.test_get_routers, 10)

    def register(self):
        self.plugin_rpc.register(self.context)
        
    def connect(self):
        asr_conn = nc_manager.connect(host="10.1.10.252",
                                      port=22,
                                      username="admin",
                                      password="!cisco123",
                                      allow_agent=False,
                                      look_for_keys=False,
                                      unknown_host_cb=lambda host,fingerprint: True,
                                      timeout=10)
        
        return asr_conn

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

    def get_all_routers(self):
        return self.plugin_rpc.get_routers(self.context)


    def start_test_loop(self, loop_fn, loop_interval):
        self.loop = loopingcall.FixedIntervalLoopingCall(loop_fn)
        self.loop.start(interval=loop_interval)

    def testloop1(self):
        print("Hello")

    def test_get_routers(self):
        routers = self.get_all_routers()
        print("routers: %s" % (routers))


VRF_REGEX = "ip vrf nrouter-(\w{6,6})"


class StandaloneService(neutron_service.Service):
    """Subclass that takes in pre-instantiated manager object instead of class name
    """

    def __init__(self, host, binary, topic, manager, report_interval=None,
                 periodic_interval=None, periodic_fuzzy_delay=None,
                 *args, **kwargs):

        self.binary = binary
        self.report_interval = report_interval
        self.manager = manager
        self.periodic_interval = periodic_interval
        self.periodic_fuzzy_delay = periodic_fuzzy_delay
        self.saved_args, self.saved_kwargs = args, kwargs
        self.timers = []
        super(neutron_service.Service, self).__init__(host, topic, manager=self.manager)



def showrun_test_main():

    conf = cfg.CONF
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    common_config.parse(sys.argv[1:])
    conf(project='neutron')

    print("ciscoconfparse test")

    server = StandaloneService.create(
        binary='showrun_test.py',
        topic=c_constants.CFG_AGENT,
        report_interval=10,
        manager=ConfigSyncTester()
    )

    service.launch(server).wait()




    return

    cfg_tester = ConfigSyncTester()
    conn = cfg_tester.connect()

    routers = cfg_tester.get_all_routers()
    print("routers: %s" % (routers))
    
    running_cfg = cfg_tester.get_running_config(conn)
    print("show run:\n%s" % (running_cfg))
    
    parsed_cfg = ciscoconfparse.CiscoConfParse(running_cfg)
    for parsed_obj in parsed_cfg.find_objects(VRF_REGEX):
        print("VRF object: %s" % (parsed_obj))
        router_id = parsed_obj.re_match(VRF_REGEX)
        print("    First 6 digits of router ID: %s\n" % (router_id))


if __name__ == "__main__":
    showrun_test_main()
