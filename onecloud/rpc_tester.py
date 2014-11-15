import sys

from neutron.openstack.common.rpc import proxy # ICEHOUSE_BACKPORT
from neutron.plugins.cisco.common import cisco_constants as c_constants
from oslo.config import cfg
from neutron.common import config as common_config


'''
How to run:
python rpc_tester.py --config-file /etc/neutron/neutron.conf
'''

class TestRPCNotifier(proxy.RpcProxy):
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=c_constants.CFG_AGENT_L3_ROUTING):
        super(TestRPCNotifier, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def test_cast(self, method_name):
        context = {}
        self.cast(context,
                  self.make_msg(method_name),
                  topic='%s.%s' % (c_constants.CFG_AGENT_L3_ROUTING,
                                   "localhost.localdomain"))


def rpc_tester_main():

    conf = cfg.CONF
    common_config.parse(sys.argv[1:])
    conf(project='neutron')

    rpc_tester = TestRPCNotifier()
    rpc_tester.test_cast("resync_asrs")

if __name__ == "__main__":
    rpc_tester_main()


 
