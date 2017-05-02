#!/usr/bin/python

# Copyright 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Class containing info about a full trace."""


import collections
import sys

from common import endpoint_cmp
from connection_info import ConnectionInfo


class TraceInfo(object):
  """A class containing a summary about a full packet trace."""

  ANALYSIS_TYPES = ['flow', 'packet']

  def __init__(self, f, analysis_type, debug=0):
    self._f = f
    assert analysis_type in self.ANALYSIS_TYPES
    self._analysis_type = analysis_type
    self._debug = debug
    self._conn = collections.OrderedDict()
    self._f.write(ConnectionInfo.header(self._analysis_type) + '\n')

  def __del__(self):
    # print connection data to out file
    for connhash in self._conn.keys():
      self._conn[connhash].print_connection_info()

  @classmethod
  def get_hash(cls, packet):
    return (('%s:%s-%s:%s-%s' % (packet.ip_src, packet.sport, packet.ip_dst,
                                 packet.dport, packet.ip_proto))
            if (endpoint_cmp(packet.ip_src, packet.sport, packet.ip_dst,
                             packet.dport) <= 0) else
            ('%s:%s-%s:%s-%s' % (packet.ip_dst, packet.dport, packet.ip_src,
                                 packet.sport, packet.ip_proto)))

  def process_packet(self, packet):
    """Process a packet."""
    # get a 4-tuple hash
    connhash = self.get_hash(packet)
    if self._debug > 0:
      sys.stderr.write('%s %s %s %s %s %s %s\n' % (
          connhash, packet.ip_src, packet.ip_dst, packet.sport, packet.dport,
          packet.timestamp, packet.ip_len))
    # only process tcp, udp, and sctp packets
    if (packet.ip_proto != 6 and packet.ip_proto != 17 and
        packet.ip_proto != 132):
      return
    # process the packet
    if connhash not in self._conn:
      self._conn[connhash] = ConnectionInfo(self._analysis_type,
                                            connhash, self._f, self._debug)
    self._conn[connhash].process_packet(packet)
