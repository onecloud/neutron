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

from oslo_log import log as logging

import oslo_messaging

LOG = logging.getLogger(__name__)


class DeviceMgrCfgRpcCallback(object):
    """Cisco cfg agent rpc support in Device mgr service plugin."""

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        self._dmplugin = plugin

    def report_non_responding_hosting_devices(self, context, host,
                                              hosting_device_ids):
        """Report that a hosting device cannot be contacted.

        @param: context - contains user information
        @param: host - originator of callback
        @param: hosting_device_ids - list of non-responding hosting devices
        @return: -
        """
        self._dmplugin.handle_non_responding_hosting_devices(
            context, host, hosting_device_ids)

    def register_for_duty(self, context, host):
        """Report that Cisco cfg agent is ready for duty.

        This function is supposed to be called when the agent has started,
        is ready to take on assignments and before any callbacks to fetch
        logical resources are issued.

        @param: context - contains user information
        @param: host - originator of callback
        @return: True if successfully registered, False if not successfully
                 registered, None if no handler found
                 If unsuccessful the agent should retry registration a few
                 seconds later
        """
        # schedule any non-handled hosting devices
        return self._dmplugin.auto_schedule_hosting_devices(context, host)

    def get_hosting_devices_for_agent(self, context, host):
        filters = {"host": [host]}
        cfg_agents = self._dmplugin.get_cfg_agents(context,
                                                   active=True,
                                                   filters=filters)
        # LOG.error("HHHHHHHH host: %s cfg_agents: %s" % (host, cfg_agents))
        if cfg_agents:
            cfg_agent = cfg_agents[0]
            hds = \
                self._dmplugin.list_hosting_devices_handled_by_cfg_agent(
                                                                  context,
                                                                  cfg_agent.id)

            for hd in hds['hosting_devices']:
                hd_db = self._dmplugin._get_hosting_device(context, hd['id'])
                creds = self._dmplugin._get_credentials(hd_db)
                hd['credentials'] = creds

            return hds

        return {"hosting_devices": []}
