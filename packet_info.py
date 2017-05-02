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


"""Class containing info about a packet."""


class PacketInfo(object):
  """A class containing a summary about a packet."""

  def __init__(self, timestamp, ip_proto, ip_src, ip_dst, ip_len,
               sport, dport, tcp_seq, tcp_len, tcp_nxtseq, tcp_ack,
               tcp_flags_syn, tcp_tsval, tcp_tsecr):
    self.timestamp = timestamp
    self.ip_proto = ip_proto
    self.ip_src = ip_src
    self.ip_dst = ip_dst
    self.ip_len = ip_len
    self.sport = sport
    self.dport = dport
    self.tcp_seq = tcp_seq
    self.tcp_len = tcp_len
    self.tcp_nxtseq = tcp_nxtseq
    self.tcp_ack = tcp_ack
    self.tcp_flags_syn = tcp_flags_syn
    self.tcp_tsval = tcp_tsval
    self.tcp_tsecr = tcp_tsecr
