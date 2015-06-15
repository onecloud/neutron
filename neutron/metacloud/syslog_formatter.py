# Copyright (c) 2015 Cisco Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
import socket
import time

import neutron.openstack.common.log as logging


class RFC5424Formatter(logging.ContextFormatter):
    """RFC5424 Syslog Formatter
    A derived formatter than allows for isotime specification
    for full RFC5424 compliance (with corrected TZ format)

    For a "proper" ISOTIME format, use "%(isotime)s" in a
    formatter instance of this class or a class derived from
    this class.  This is for a work-around where strftime
    has no mechanism to produce timezone in the format of
    "-08:00" as required by RFC5424.

    The '%(isotime)s' replacement will read in the record
    timestamp and try and reparse it.  This really is a
    problem with RFC5424 and strftime.  I am unsure if this
    will be fixed in the future (in one or the other case)

    This formatter has an added benefit of allowing for
    '%(hostname)s' to be specified which will return a '-'
    as specified in RFC5424 if socket.gethostname() returns
    bad data (exception).

    The RFC5424 format string should look something like:

    %(isotime)s %(hostname)s %(name)s %(process)d - - %(message)s

    The section after the two "- -" is technically the message
    section, and can have any data applied to it e.g.:

        <...> %(levelname)s [%(module)s %(funcName)s] %(message)s

    The '- -' section is the "msg ID" and "Structured-Data" Elements,
    respectively

    MSGID (Description from RFC5424):
       The MSGID SHOULD identify the type of message.  For example, a
    firewall might use the MSGID "TCPIN" for incoming TCP traffic and the
    MSGID "TCPOUT" for outgoing TCP traffic.  Messages with the same
    MSGID should reflect events of the same semantics.  The MSGID itself
    is a string without further semantics.  It is intended for filtering
    messages on a relay or collector.
    The NILVALUE SHOULD be used when the syslog application does not, or
    cannot, provide any value.

    Stuctured Data Example:
        [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
    """
    def __init__(self, *args, **kwargs):
        try:
            self._hostname = socket.gethostname()
        except Exception:
            self._hostname = '-'
        self._is_dst = None
        self._tz_offset = self._set_tz_offset()

        super(RFC5424Formatter, self).__init__(*args, **kwargs)

    def _set_tz_offset(self):
        """Returns the offset from UTC as +/-HH:MM. Since the offset only
        changes twice per year, and even then only in certain locales,
        also try to avoid doing unnecessary work.
        """
        if time.timezone == 0:
            return 'Z'

        is_dst = time.localtime().tm_isdst
        if is_dst == self._is_dst:
            return self._tz_offset

        self._is_dst = is_dst
        if self._is_dst:
            offset = -(time.altzone / 60)
        else:
            offset = -(time.timezone / 60)

        return '%+03d:%02d' % (offset / 60, offset % 60)

    def format(self, record):
        record.__dict__['hostname'] = self._hostname

        # If we're set to a timezone that ignores DST, then we can keep
        # using the offset we got on initialization forever, as it's never
        # going to change.
        if time.daylight:
            self._tz_offset = self._set_tz_offset()

        record.__dict__['isotime'] = datetime.datetime.fromtimestamp(
            record.created).isoformat() + self._tz_offset

        return super(RFC5424Formatter, self).format(record)
