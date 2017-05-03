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


"""Class containing info about a connection."""


import sys
import numpy as np

from common import endpoint_cmp
from common import TCP_SEQ_MAX_VALUE
from modulo import Modulo


class ConnectionInfo(object):
  """A class containing a summary about a 5-tuple connection."""

  def __init__(self, analysis_type, connhash, f, debug):
    self._analysis_type = analysis_type
    self._connhash = connhash
    self._f = f
    self._debug = debug
    self._ip_total_pkt = 0
    self._ip_total_bytes = 0
    self._seq = Modulo(TCP_SEQ_MAX_VALUE)

  def endpoint(self, addr, port):
    return '%s:%s' % (addr, port)

  @classmethod
  def header(cls, analysis_type):
    if analysis_type == 'flow':
      return cls.flow_header()
    elif analysis_type == 'packet':
      return cls.packet_header()

  def process_packet(self, packet):
    """Main packet processing method."""
    self.common_process_packet(packet)
    self.flow_process_packet(packet)
    self.packet_process_packet(packet)
    self._ip_total_pkt += 1

  def common_process_packet(self, packet):
    # first packet of the connection
    if self._ip_total_pkt == 0:
      self._ip_proto = packet.ip_proto
      # sort the connection
      if endpoint_cmp(packet.ip_src, packet.sport, packet.ip_dst,
                      packet.dport) <= 0:
        self._ip_src = packet.ip_src
        self._ip_dst = packet.ip_dst
        self._sport = packet.sport
        self._dport = packet.dport
      else:
        self._ip_src = packet.ip_dst
        self._ip_dst = packet.ip_src
        self._sport = packet.dport
        self._dport = packet.sport
      self._src = self.endpoint(self._ip_src, self._sport)
      self._dst = self.endpoint(self._ip_dst, self._dport)

  @classmethod
  def packet_header(cls):
    return '#%s %s %s %s %s %s' % (
        'type',
        'src',
        'dst',
        'timestamp',
        'delta',
        'other')

  def packet_process_packet(self, packet):
    """Process a packet for this connection (packet mode)."""
    src = self.endpoint(packet.ip_src, packet.sport)
    dst = self.endpoint(packet.ip_dst, packet.dport)
    # append new data segments
    if self._debug > 0:
      sys.stderr.write('%s %s %s %s %s %s\n' % (
          packet.timestamp, src, dst, packet.tcp_len, packet.tcp_nxtseq,
          packet.tcp_ack))
    self.packet_process_delta1(src, dst, packet)
    self.packet_process_delta2(src, dst, packet)
    self.packet_process_delta3(src, dst, packet)
    self.packet_process_delta4(src, dst, packet)

  def packet_process_delta1(self, src, dst, packet):
    """delta1: match data segments with the first ACK that acks them."""
    if self._ip_total_pkt == 0:
      # segments with data that have not been ACKed yet
      self._tcp_unacked_segments = {
          src: [],
          dst: [],
      }
      self._tcp_ack_highest = {
          src: None,
          dst: None,
      }
      self._delta1_list = {
          src: [],
          dst: [],
      }
    if packet.tcp_len > 0:
      # detect and delete duplicate data segments
      is_duplicate = any([(tcp_nxtseq == packet.tcp_nxtseq)
                          for (_, _, tcp_nxtseq)
                          in self._tcp_unacked_segments[src]])
      if is_duplicate:
        # remove all the duplicates
        new_list = []
        for l in self._tcp_unacked_segments[src]:
          _, _, tcp_nxtseq = l
          if tcp_nxtseq == packet.tcp_nxtseq:
            continue
          new_list += [l]
        self._tcp_unacked_segments[src] = new_list
      else:
        self._tcp_unacked_segments[src] += [[packet.timestamp, packet.tcp_len,
                                             packet.tcp_nxtseq]]
    new_ack_value = False
    if packet.tcp_ack is not None:
      if self._tcp_ack_highest[src] is None:
        self._tcp_ack_highest[src] = packet.tcp_ack
        new_ack_value = True
      else:
        if self._seq.cmp(self._tcp_ack_highest[src], packet.tcp_ack) < 0:
          new_ack_value = True
          self._tcp_ack_highest[src] = packet.tcp_ack
    if not new_ack_value:
      return
    # check for already-acked data
    new_list = []
    for l in self._tcp_unacked_segments[dst]:
      timestamp, _, tcp_nxtseq = l
      if self._seq.cmp(tcp_nxtseq, self._tcp_ack_highest[src]) <= 0:
        # segment has been acked
        delta1 = packet.timestamp - timestamp
        if delta1 > 1.0:
          if self._debug > 0:
            print 'delta1: should remove [%f, %s, %s]' % (
                timestamp, _, tcp_nxtseq)
        if self._analysis_type == 'flow':
          self._delta1_list[src] += [delta1]
        elif self._analysis_type == 'packet':
          # emit delta1 line
          # (note that we are reversing src and dst as the information
          # we have right now refers to the ACK, which goes in the reverse
          # direction than the segment we care about)
          self._f.write('%s %f %s %s %f -\n' % ('delta1', timestamp,
                                                dst, src, delta1))
      else:
        new_list += [l]
    self._tcp_unacked_segments[dst] = new_list

  def packet_process_delta2(self, src, dst, packet):
    """delta2: match segments with the first TSecr that "acks" its TSval."""
    if self._ip_total_pkt == 0:
      # segments with tsval that have not been "ACKed" by a tsecr yet
      self._tcp_untsecred_segments = {
          src: [],
          dst: [],
      }
      self._tcp_tsecr_highest = {
          src: None,
          dst: None,
      }
    if packet.tcp_tsval is None or packet.tcp_tsecr is None:
      return
    # we can only assume cause-effect on pure ACKs
    if packet.tcp_len > 0:
      self._tcp_untsecred_segments[src] += [[
          packet.timestamp, packet.tcp_tsval]]
      # TODO(chema): detect and delete duplicate data segments
    new_tsecr_value = False
    if packet.tcp_tsecr is not None:
      if self._tcp_tsecr_highest[src] is None:
        self._tcp_tsecr_highest[src] = packet.tcp_tsecr
        new_tsecr_value = True
      else:
        if self._tcp_tsecr_highest[src] < packet.tcp_tsecr:
          new_tsecr_value = True
          self._tcp_tsecr_highest[src] = packet.tcp_tsecr
    if not new_tsecr_value:
      return
    # check for already-tsecr'ed segments
    new_list = []
    for l in self._tcp_untsecred_segments[dst]:
      timestamp, tcp_tsval = l
      if tcp_tsval <= self._tcp_tsecr_highest[src]:
        # tsval has been tsecr'ed
        delta2 = packet.timestamp - timestamp
        if delta2 > 1.0:
          print 'delta2: should remove [%f, %s]' % (timestamp, tcp_tsval)
        if self._analysis_type == 'packet':
          # emit delta2 line
          # (note that we are reversing src and dst as the information
          # we have right now refers to the TSecr, which goes in the reverse
          # direction than the segment we care about)
          self._f.write('%s %f %s %s %f -\n' % ('delta2', timestamp,
                                                dst, src, delta2))
      else:
        new_list += [l]
    self._tcp_untsecred_segments[dst] = new_list

  POPULAR_HZ_VALUES = [100., 200., 250., 1000.]

  def estimate_hz(self, packet, src):
    """Estimate the HZ of a host by comparing the ts and TSval of 2 packets."""
    ref_timestamp, ref_tcp_tsval = self._reference_tcp_tsval[src]
    estimated_hz = ((packet.tcp_tsval - ref_tcp_tsval) /
                    (packet.timestamp - ref_timestamp))
    # round the estimated HZ to a popular value
    error_l = [abs((estimated_hz - hz) / hz) for hz in self.POPULAR_HZ_VALUES]
    pos = error_l.index(min(error_l))
    if min(error_l) > 0.05:
      # invalid HZ
      print 'error: unexpected estimated HZ (src: %s, %f = %f + %.2f%%)' % (
          src, estimated_hz, self.POPULAR_HZ_VALUES[pos], 100 * min(error_l))
      return -1
    return self.POPULAR_HZ_VALUES[pos]

  def packet_process_delta3(self, src, dst, packet):
    """delta3: estimate the sender's delay variance from the TSval."""
    if self._ip_total_pkt == 0:
      self._reference_tcp_tsval = {
          src: None,
          dst: None,
      }
      self._estimated_hz = {
          src: None,
          dst: None,
      }
    if packet.tcp_tsval is None or packet.tcp_tsecr is None:
      return
    if self._reference_tcp_tsval[src] is None:
      self._reference_tcp_tsval[src] = [packet.timestamp, packet.tcp_tsval]
      return
    ref_timestamp, ref_tcp_tsval = self._reference_tcp_tsval[src]
    if self._estimated_hz[src] is None:
      self._estimated_hz[src] = self.estimate_hz(packet, src)
    if self._estimated_hz[src] == -1:
      return
    expected_timestamp = ref_timestamp + ((packet.tcp_tsval - ref_tcp_tsval) /
                                          self._estimated_hz[src])
    delta3 = packet.timestamp - expected_timestamp
    if self._analysis_type == 'packet':
      # emit delta3 line
      if delta3 > 1.0:
        print 'delta3: should remove [%f, %s]' % (packet.timestamp, delta3)
      self._f.write('%s %f %s %s %f -\n' % ('delta3', packet.timestamp,
                                            src, dst, delta3))

  def packet_process_delta4(self, src, dst, packet):
    """delta4: match consecutive segments from the same src."""
    if self._ip_total_pkt == 0:
      self._last_timestamp_from = {
          'ack': {
              src: None,
              dst: None,
          },
          'data': {
              src: None,
              dst: None,
          },
      }
    traffic = 'ack' if packet.tcp_len == 0 else 'data'
    if self._last_timestamp_from[traffic][src] is not None:
      delta4 = packet.timestamp - self._last_timestamp_from[traffic][src]
      if self._analysis_type == 'packet':
        # emit delta4 line
        self._f.write('%s %f %s %s %f %s\n' % ('delta4', packet.timestamp,
                                               src, dst, delta4, traffic))
    self._last_timestamp_from[traffic][src] = packet.timestamp

  @classmethod
  def flow_header(cls):
    return '#%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' % (
        'connhash',
        'first_ts',
        'last_ts',
        'ip_proto',
        'tcp_seq_syn[src]',
        'tcp_seq_syn[dst]',
        'ip_total_pkt',
        'ip_total_bytes',
        'pps',
        'ip_bitrate',
        'tcp_bytes',
        'tcp_goodput_bytes',
        'tcp_goodput_bitrate',
        'delta1_small_mean',
        'delta1_small_median',
        'delta1_large_mean',
        'delta1_large_median')

  def flow_process_packet(self, packet):
    """Process a packet for this connection (flow mode)."""
    # first packet of the connection
    src = self.endpoint(packet.ip_src, packet.sport)
    dst = self.endpoint(packet.ip_dst, packet.dport)
    if self._ip_total_pkt == 0:
      self._first_ts = packet.timestamp
      # init connection values
      self._tcp_seq_syn = {
          src: None,
          dst: None,
      }
      self._tcp_seq_first = {
          src: None,
          dst: None,
      }
      self._tcp_seq_last = {
          src: None,
          dst: None,
      }
      self._tcp_total_bytes = {
          src: 0,
          dst: 0,
      }
    # SYN packet
    if packet.tcp_flags_syn:
      self._tcp_seq_syn[src] = packet.tcp_seq
    # any packet: manage time
    self._last_ts = packet.timestamp
    # any packet: manage bytes
    self._ip_total_bytes += packet.ip_len
    self._tcp_total_bytes[src] += packet.tcp_len
    if self._tcp_seq_first[src] is None:
      self._tcp_seq_first[src] = packet.tcp_seq
    nxtseq = (packet.tcp_nxtseq if packet.tcp_nxtseq is not None
              else packet.tcp_seq)
    if self._tcp_seq_last[src] is None:
      self._tcp_seq_last[src] = nxtseq
    else:
      self._tcp_seq_last[src] = self._seq.max(self._tcp_seq_last[src], nxtseq)

  def print_connection_info(self):
    """Prints information about a full connection (flow mode)."""
    if self._analysis_type == 'packet':
      return
    pps = '-'
    ip_bitrate = '-'
    tcp_bytes = '-'
    tcp_goodput_bitrate = '-'
    tcp_goodput_bytes = '-'
    if self._first_ts != self._last_ts:
      pps = self._ip_total_pkt / (self._last_ts - self._first_ts)
      ip_bitrate = (8. * self._ip_total_bytes /
                    (self._last_ts - self._first_ts))
      tcp_bytes = (self._tcp_total_bytes[self._src] +
                   self._tcp_total_bytes[self._dst])
      tcp_goodput_bytes = 0
      tcp_goodput_bytes += self._seq.diff(self._tcp_seq_last[self._src],
                                          self._tcp_seq_first[self._src])
      tcp_goodput_bytes += self._seq.diff(self._tcp_seq_last[self._dst],
                                          self._tcp_seq_first[self._dst])
      tcp_goodput_bitrate = (8. * tcp_goodput_bytes /
                             (self._last_ts - self._first_ts))
      if (np.median(self._delta1_list[self._src]) <
          np.median(self._delta1_list[self._dst])):
        small_median = np.median(self._delta1_list[self._src])
        small_mean = np.mean(self._delta1_list[self._src])
        large_median = np.median(self._delta1_list[self._dst])
        large_mean = np.mean(self._delta1_list[self._dst])
      else:
        small_median = np.median(self._delta1_list[self._dst])
        small_mean = np.mean(self._delta1_list[self._dst])
        large_median = np.median(self._delta1_list[self._src])
        large_mean = np.mean(self._delta1_list[self._src])
      self._f.write('%s %f %f %s %s %s %i %i %f %f %i %i %f %f %f %f %f\n' % (
          self._connhash, self._first_ts, self._last_ts,
          self._ip_proto,
          self._tcp_seq_syn[self._src], self._tcp_seq_syn[self._dst],
          self._ip_total_pkt, self._ip_total_bytes,
          pps, ip_bitrate, tcp_bytes,
          tcp_goodput_bytes, tcp_goodput_bitrate,
          small_mean, small_median, large_mean, large_median))
