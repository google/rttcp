#!/usr/bin/python

"""Packet dumper."""


import subprocess
import sys

from packet_info import PacketInfo
from trace_info import TraceInfo


class PacketDumper(object):
  """A class used to cherry-pick data from a packet trace (tshark)."""

  def __init__(self, tshark_bin, infile, outfile, analysis_type, debug):
    self._tshark_bin = tshark_bin
    self._infile = infile
    self._outfile = outfile
    self._analysis_type = analysis_type
    self._debug = debug

  def create_command(self):
    """Create the right tshark command."""
    tshark_opts = ['-n', '-T', 'fields', '-E', 'separator=;']
    # required to get absolute (raw) tcp seq numbers
    tshark_opts += ['-o', 'tcp.relative_sequence_numbers: false']
    tshark_opts += ['-e', 'frame.time_epoch']
    tshark_opts += ['-e', 'ip.proto']
    tshark_opts += ['-e', 'ip.src']
    tshark_opts += ['-e', 'ip.dst']
    tshark_opts += ['-e', 'ip.len']
    tshark_opts += ['-e', 'tcp.srcport']
    tshark_opts += ['-e', 'tcp.dstport']
    tshark_opts += ['-e', 'tcp.seq']
    tshark_opts += ['-e', 'tcp.len']
    tshark_opts += ['-e', 'tcp.nxtseq']
    tshark_opts += ['-e', 'tcp.ack']
    tshark_opts += ['-e', 'tcp.flags.syn']
    tshark_opts += ['-e', 'tcp.options.timestamp.tsval']
    tshark_opts += ['-e', 'tcp.options.timestamp.tsecr']
    command = [self._tshark_bin] + tshark_opts + ['-r', self._infile]
    return command

  def parse_line(self, line):
    """Parses the output of a tshark line."""
    try:
      (timestamp, ip_proto, ip_src, ip_dst, ip_len,
       sport, dport, tcp_seq, tcp_len, tcp_nxtseq, tcp_ack,
       tcp_flags_syn, tcp_tsval, tcp_tsecr) = line[:-1].split(';')
    except ValueError:
      sys.stderr.write('discarding line = "%s"\n' % line)
      raise
    timestamp = float(timestamp)
    # if there are multiple IP values, use the last one
    if ',' in ip_proto:
      ip_proto = ip_proto.split(',')[-1]
    ip_proto = int(ip_proto)
    if ',' in ip_src:
      ip_src = ip_src.split(',')[-1]
    if ',' in ip_dst:
      ip_dst = ip_dst.split(',')[-1]
    if ',' in ip_len:
      ip_len = ip_len.split(',')[-1]
    ip_len = int(ip_len)
    # sanitize tcp values
    tcp_seq = int(tcp_seq)
    tcp_len = int(tcp_len)
    tcp_nxtseq = int(tcp_nxtseq) if tcp_nxtseq else None
    tcp_ack = int(tcp_ack) if tcp_ack else None
    tcp_flags_syn = int(tcp_flags_syn)
    tcp_tsval = int(tcp_tsval)
    tcp_tsecr = int(tcp_tsecr)
    return PacketInfo(timestamp, ip_proto, ip_src, ip_dst, ip_len,
                      sport, dport, tcp_seq, tcp_len, tcp_nxtseq, tcp_ack,
                      tcp_flags_syn, tcp_tsval, tcp_tsecr)

  def run(self):
    # prepare the output fd
    # we cannot use controlled execution (`with open(...) as f:`) as we want
    # to support sys.stdout too.
    f = (open(self._outfile, 'w+') if self._outfile != sys.stdout else
         sys.stdout)
    try:
      # init trace info object
      trace_info = TraceInfo(f, self._analysis_type, self._debug)
      # run command
      command = self.create_command()
      if self._debug > 0:
        sys.stderr.write(' '.join(command) + '\n')
      proc = subprocess.Popen(command, stdout=subprocess.PIPE)
      # process the output
      for line in iter(proc.stdout.readline, ''):
        try:
          packet = self.parse_line(line)
        except ValueError:
          continue
        trace_info.process_packet(packet)
      # clean up trace object
      del trace_info
    finally:
      if self._outfile != sys.stdout:
        f.close()
