#!/usr/bin/python

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
