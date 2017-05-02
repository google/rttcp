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


"""Plotting code."""


from functools import partial
import sys

from common import decimal_fmt
import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import pandas as pd


MAX_SEPARATE = 5
CUT_VALUE_HEAD_SECS = 0.01
CUT_VALUE_TAIL_SECS = 0.1
NUM_BINS = 50
NUM_LARGEST_BINS = 10
MIN_SEPARATION = 0.05
MIN_FLOW_GOODPUT = 5000000


DIR_CONN_COLOR_D = {
    'delta1': {
        'fwd': ['darkblue', 'x'],
        'rev': ['darkgreen', 'x'],
    },
    'delta2': {
        'fwd': ['darkblue', 'x'],
        'rev': ['darkgreen', 'x'],
    },
    'delta3': {
        'fwd': ['blue', 'x'],
        'rev': ['green', 'x'],
    },
    'delta4': {
        'fwd': ['blue', 'x'],
        'rev': ['green', 'x'],
    },
}

IP_CONN_COLOR_D = {
    0: ['g', 'o'],
    1: ['r', 'v'],
    2: ['c', '^'],
    3: ['m', '>'],
    4: ['y', '<'],
    5: ['k', 'o'],
    6: ['g', 'v'],
    7: ['r', '^'],
    8: ['c', '>'],
    9: ['m', '<'],
    'remaining': ['b', 'x'],
}


class Plotter(object):
  """Class that processes analyzed files and plots them."""

  def __init__(self, infile, outfile, analysis_type, plot_format,
               plot_title, src_reverse, debug):
    self._infile = infile
    self._outfile = outfile
    self._analysis_type = analysis_type
    self._plot_format = plot_format
    self._plot_title = plot_title
    self._src_reverse = src_reverse
    self._debug = debug
    milli = 1e-3
    self._format_milli = ticker.FuncFormatter(
        lambda y, pos: '{0:g}'.format(y / milli))
    kilo = 1e+3
    self._format_kilo = ticker.FuncFormatter(
        lambda y, pos: '{0:g}'.format(y / kilo))
    mega = 1e+6
    self._format_mega = ticker.FuncFormatter(
        lambda y, pos: '{0:g}'.format(y / mega))
    cent = 100
    self._format_percent = ticker.FuncFormatter(
        lambda y, pos: '{0:g}'.format(y * cent))

  def run(self):
    """Plot a result file obtained from the pcap analysis."""
    df = self.read_input()
    if self._analysis_type == 'flow':
      self.flow_process_data(df)
    elif self._analysis_type == 'packet':
      self.packet_process_data(df)

  def read_input(self):
    """Read an input file into a pandas dataframe."""
    # prepare the input fd
    # we cannot use controlled execution (`with open(...) as f:`) as we want
    # to support sys.stdin too.
    f = (open(self._infile, 'r') if self._infile != sys.stdin else sys.stdin)
    try:
      if self._analysis_type == 'flow':
        df = self.flow_read_input(f)
      elif self._analysis_type == 'packet':
        df = self.packet_read_input(f)
    finally:
      if self._infile != sys.stdin:
        f.close()
    return df

  def flow_read_input(self, f):
    """Read input file into a pandas dataframe (flow type)."""
    lst = []
    i = 0
    for line in f:
      try:
        (connhash, first_ts, last_ts,
         ip_proto,
         tcp_seq_syn_sport, tcp_seq_syn_dport,
         ip_total_pkt, ip_total_bytes,
         pps, ip_bitrate, tcp_bytes,
         tcp_goodput_bytes, tcp_goodput_bitrate,
         delta1_small_mean,
         delta1_small_median,
         delta1_large_mean,
         delta1_large_median) = line.split()
      except ValueError:
        sys.stderr.write('discarding line = "%s"\n' % line)
        continue
      if line[0] == '#':
        # this is a comment
        continue
      if self._debug > 0:
        sys.stderr.write('%s\n' % line)
      if pps == '-' or ip_bitrate == '-':
        continue
      lst += [[i, connhash, float(first_ts), float(last_ts),
               int(ip_proto),
               tcp_seq_syn_sport, tcp_seq_syn_dport,
               int(ip_total_pkt), int(ip_total_bytes),
               float(pps), float(ip_bitrate), int(tcp_bytes),
               int(tcp_goodput_bytes), float(tcp_goodput_bitrate),
               float(delta1_small_mean), float(delta1_small_median),
               float(delta1_large_mean), float(delta1_large_median)]]
      i += 1
    df = pd.DataFrame(lst, columns=['order', 'connhash', 'first_ts', 'last_ts',
                                    'ip_proto',
                                    'tcp_seq_syn_sport', 'tcp_seq_syn_dport',
                                    'ip_total_pkt', 'ip_total_bytes',
                                    'pps', 'ip_bitrate', 'tcp_bytes',
                                    'tcp_goodput_bytes', 'tcp_goodput_bitrate',
                                    'delta1_small_mean', 'delta1_small_median',
                                    'delta1_large_mean', 'delta1_large_median'])
    return df

  def packet_read_input(self, f):
    """Read input file into a pandas dataframe (packet type)."""
    lst = []
    i = 0
    for line in f:
      try:
        t, timestamp, src, dst, delta = line.split()
      except ValueError:
        sys.stderr.write('discarding line = "%s"\n' % line)
        continue
      if line[0] == '#':
        # this is a comment
        continue
      if self._debug > 0:
        sys.stderr.write('%s\n' % line)
      lst += [[i, t, float(timestamp), src, dst, float(delta)]]
      i += 1
    df = pd.DataFrame(lst, columns=['order', 'type', 'timestamp', 'src', 'dst',
                                    'delta'])
    return df

  def flow_process_data(self, df):
    """Process a pandas dataframe (flow mode)."""
    # create the matplotlib figure
    fig = plt.figure(figsize=(9, 7))
    # ax_pps = fig.add_subplot(5, 1, 1)
    ax_tcp_rate = fig.add_subplot(4, 1, 1)
    ax_delta1 = fig.add_subplot(4, 1, 2)
    ax_tcp_total = fig.add_subplot(4, 1, 3)
    ax_tcp_extra_bytes = fig.add_subplot(4, 1, 4)
    # ax_ip_rate = fig.add_subplot(4, 1, 4)

    # shift x axis
    time_shift = int(df[:1].first_ts)
    format_shift = ticker.FuncFormatter(
        lambda x, pos: '{0:g}'.format(x - time_shift))
    for ax in (ax_tcp_rate, ax_delta1, ax_tcp_total, ax_tcp_extra_bytes):
      ax.xaxis.set_major_formatter(format_shift)

    # scale y axis
    # ax_pps.yaxis.set_major_formatter(self._format_kilo)
    ax_tcp_rate.yaxis.set_major_formatter(self._format_mega)
    ax_tcp_total.yaxis.set_major_formatter(self._format_mega)
    ax_tcp_extra_bytes.yaxis.set_major_formatter(self._format_percent)
    ax_delta1.yaxis.set_major_formatter(self._format_milli)
    # ax_ip_rate.yaxis.set_major_formatter(self._format_mega)

    # ax_delta1.plot(df.first_ts, df.delta1_large_mean,
    #                linestyle='', marker='v',
    #                color='g', markersize=3)

    # select tcp flows only
    df_tcp = df[(df.ip_proto == 6)]
    label, color, marker = 'tcp', 'b', 'x'
    # ax_pps.plot(df_tcp.first_ts, df_tcp.ip_total_pkt,
    #            label=label, linestyle='', marker=marker,
    #            color=color, markersize=3)

    # plot TCP flow goodput
    ax_tcp_rate.plot(df_tcp.first_ts, df_tcp.tcp_goodput_bitrate,
                     label=label, linestyle='', marker=marker,
                     color=color, markersize=3)
    tcp_goodput_quantile_01 = df_tcp.tcp_goodput_bitrate.quantile(q=0.01)
    ax_tcp_rate.axhline(y=tcp_goodput_quantile_01, color='g',
                        ls='dotted', lw=0.5)
    tcp_goodput_quantile_50 = df_tcp.tcp_goodput_bitrate.quantile(q=0.50)
    ax_tcp_rate.axhline(y=tcp_goodput_quantile_50, color='g',
                        ls='dashed', lw=0.5)
    tcp_goodput_quantile_99 = df_tcp.tcp_goodput_bitrate.quantile(q=0.99)
    ax_tcp_rate.axhline(y=tcp_goodput_quantile_99, color='g',
                        ls='dotted', lw=0.5)
    # zoom on around the median
    ax_tcp_rate.set_ylim([0, 10 * tcp_goodput_quantile_50])
    # add a label with the median
    ax_tcp_rate.text(time_shift, tcp_goodput_quantile_50,
                     decimal_fmt(tcp_goodput_quantile_50, 'bps'),
                     fontsize='x-small')

    # plot flow media delta1
    ax_delta1.plot(df_tcp.first_ts, df_tcp.delta1_large_median,
                   linestyle='', marker='x',
                   color='b', markersize=3)
    delta1_quantile_01 = df_tcp.delta1_large_median.quantile(q=0.01)
    ax_delta1.axhline(y=delta1_quantile_01, color='g', ls='dotted', lw=0.5)
    delta1_quantile_50 = df_tcp.delta1_large_median.quantile(q=0.50)
    ax_delta1.axhline(y=delta1_quantile_50, color='g', ls='dashed', lw=0.5)
    delta1_quantile_99 = df_tcp.delta1_large_median.quantile(q=0.99)
    ax_delta1.axhline(y=delta1_quantile_99, color='g', ls='dotted', lw=0.5)
    # zoom on around the median
    ax_delta1.set_ylim([0, 10 * delta1_quantile_50])
    # add a label with the median
    ax_delta1.text(time_shift, delta1_quantile_50,
                   '%s' % decimal_fmt(delta1_quantile_50, 'sec'),
                   fontsize='x-small')

    # plot flow goodput (absolute)
    ax_tcp_total.plot(df_tcp.first_ts, df_tcp.tcp_goodput_bytes,
                      label=label, linestyle='', marker=marker,
                      color=color, markersize=3)
    tcp_bytes_quantile_50 = df_tcp.tcp_goodput_bytes.quantile(q=0.50)
    ax_tcp_total.axhline(y=tcp_bytes_quantile_50, color='g',
                         ls='dashed', lw=0.5)
    tcp_extra_percent = ((df_tcp.tcp_bytes - df_tcp.tcp_goodput_bytes) /
                         df_tcp.tcp_goodput_bytes)
    ax_tcp_extra_bytes.plot(df_tcp.first_ts, tcp_extra_percent,
                            label=label, linestyle='', marker=marker,
                            color=color, markersize=3)
    ax_tcp_extra_bytes.axhline(y=0, color='k', ls='solid', lw=0.5)
    ax_tcp_extra_bytes.axhline(y=tcp_extra_percent.mean(), color='g',
                               ls='dashed', lw=0.5)

    # ax_ip_rate.plot(df_tcp.first_ts, df_tcp.ip_bitrate,
    #                label=label, linestyle='', marker=marker,
    #                color=color, markersize=3)
    total_line = 'total { flows: %s pkt: %s ip_bytes: %s }' % (
        decimal_fmt(len(df_tcp), ''),
        decimal_fmt(sum(df_tcp['ip_total_pkt']), 'pkt'),
        decimal_fmt(sum(df_tcp['ip_total_bytes']), 'B'))
    tcp_flows_over_threshold = len(
        df_tcp[(df_tcp.tcp_goodput_bitrate > MIN_FLOW_GOODPUT)])
    total_line += '\ntcp_goodput { median: %s percent_over_%s: %f } ' % (
        decimal_fmt(tcp_goodput_quantile_50, 'bps'),
        decimal_fmt(MIN_FLOW_GOODPUT, 'bps'),
        100.0 * tcp_flows_over_threshold / len(df_tcp))
    total_line += '\ndelta1 { median: %s } ' % (
        decimal_fmt(delta1_quantile_50, 'sec'))

    ax_tcp_extra_bytes.set_xlabel('Flow Start (sec) -- ' + total_line,
                                  fontsize='small')
    # ax_pps.set_ylabel('Flow Throughput (Kpps)')
    ax_tcp_rate.set_ylabel('Flow Goodput\n(Mbps)')
    ax_delta1.set_ylabel('Flow Median\ndelta1 (msec)')
    ax_tcp_total.set_ylabel('Flow Goodput\n(MB)')
    ax_tcp_extra_bytes.set_ylabel('Flow Extra\nTCP Bytes (%)')
    # ax_ip_rate.set_ylabel('Flow IP Throughput (Mbps)')
    # ax_tcp_total.legend()
    ax_tcp_rate.set_title(self._plot_title)
    plt.savefig(self._outfile, format=self._plot_format)

  def packet_process_data(self, df):
    """Process a pandas dataframe (packet mode)."""
    # create the matplotlib figure
    fig = plt.figure(figsize=(9, 7))
    fig.subplots_adjust(hspace=.4)
    fig.canvas.set_window_title('packet_process_data')

    delta_l = ('delta1', 'delta2', 'delta3', 'delta4')
    print_distro = False
    graph_l = ['time',]
    if print_distro:
      graph_l.append('distro')

    outer_grid = gridspec.GridSpec(2 * (2 if print_distro else 1), 2)
    if print_distro:
      position_l = ((0, 0), (1, 0),
                    (0, 1), (1, 1),
                    (2, 0), (3, 0),
                    (2, 1), (3, 1),
                   )
    else:
      position_l = ((0, 0), (0, 1),
                    (1, 0), (1, 1)
                   )

    # split the data depending on the direction
    def match_direction(reverse, x):
      addr = x['src']
      if ':' in addr:
        addr, _ = addr.split(':', 1)
      if not reverse or not addr.startswith(reverse):
        return 'fwd'
      else:
        return 'rev'
    bound_match_direction = partial(match_direction, self._src_reverse)
    df['dir'] = df.apply(bound_match_direction, axis=1)

    i = 0
    ax = {}
    subplot_spec = {}
    for delta in delta_l:
      ax[delta] = {}
      subplot_spec[delta] = {}
      # get the data frame to analyze here
      data = {}
      for d in ('fwd', 'rev'):
        data[d] = df[(df.dir == d) & (df.type == delta)]
        if delta == 'delta4':
          # remove the heads of the trains (hystart_ack_delta in tcp_cubic.c)
          data[d] = data[d][(data[d].delta < 0.002)]
      # print the data frames
      for graph in graph_l:
        # ax[delta][graph] = fig.add_subplot(4, 2, position_l[i])
        subplot_spec[delta][graph] = outer_grid[position_l[i][0],
                                                position_l[i][1]]
        ax[delta][graph] = plt.subplot(subplot_spec[delta][graph])

        if graph == 'time':
          # print the time series
          ax[delta][graph] = self.add_timeseries_graph(
              delta, ax[delta][graph], subplot_spec[delta][graph], data)
        elif graph == 'distro':
          # print the distribution
          self.add_distribution_graph(delta, ax[delta][graph], data)
        i += 1

    # main title
    plt.suptitle(self._plot_title, fontsize='x-small')

    # synchronize the y axes for delta1 and delta2
    ymin_l = []
    ymax_l = []
    for delta in ('delta1', 'delta2'):
      for vax in ax[delta]['time']:
        ymin, ymax = vax.get_ylim()
        ymin_l.append(ymin)
        ymax_l.append(ymax)
    ymin = min(ymin_l)
    ymax = max(ymax_l)
    for delta in ('delta1', 'delta2'):
      for vax in ax[delta]['time']:
        vax.set_ylim(ymin, ymax)
    # add the legend
    ax['delta1']['time'][1].legend(prop={'size': 'xx-small'})

    plt.savefig(self._outfile, format=self._plot_format)

  def add_timeseries_graph(self, delta, _, subplot_spec, data):
    """Print the time series."""
    total_line = '%s' % delta
    time_shift = {}

    # ensure there is at least some non-empty dataframes
    # pylint: disable=g-explicit-length-test
    if all([len(df) == 0 for df in data.values()]):
      print 'error: no actual data for %s' % delta
      return
    # pylint: enable=g-explicit-length-test

    # split the plot in 2 uneven parts
    inner_grid = gridspec.GridSpecFromSubplotSpec(1, 5, subplot_spec)
    axl = plt.subplot(inner_grid[0, 0])
    axl.xaxis.set_ticks_position('none')
    axl.yaxis.set_ticks_position('left')
    axr = plt.subplot(inner_grid[0, 1:])
    axr.yaxis.set_ticks_position('right')
    axr.tick_params(labeltop='off', labelright='off')

    for i in range(len(data)):
      df_local = data.values()[i]
      if len(df_local) == 0:  # pylint: disable=g-explicit-length-test
        continue
      d = data.keys()[i]
      color, marker = DIR_CONN_COLOR_D[delta][d]

      # get the time series label
      label = '%s "src %s %s"' % (d, '==' if d == 'rev' else '!=',
                                  self._src_reverse)
      # get x-axis shift
      time_shift[d] = int(df_local[:1].timestamp)
      df_all = df_local

      # for (src, dst, color, marker) in separate_conn_l:
      #   df_conn = df_all[(df_all.src == src) & (df_all.dst == dst)]
      #   label = '%s->%s' % (df_conn.src.iloc[0], df_conn.dst.iloc[0])
      #   ax[delta]['time'].plot(df_conn.timestamp, df_conn.delta,
      #                          label=label, linestyle='-', marker=marker,
      #                          color=color, markersize=3)
      #   # remove the connection
      #   df_all = df_all[(df_all.src != src) | (df_all.dst != dst)]

      # print the time series
      axr.plot(df_all.timestamp, df_all.delta,
               linestyle='', marker=marker,
               label=label,
               color=color, markersize=3)

      # calculate the delta percentiles
      delta_quantile_50 = df_local.delta.quantile(q=0.50)
      delta_mean = df_local.delta.mean()
      delta_stddev = df_local.delta.std()

      # print delta percentile lines
      axr.axhline(y=delta_quantile_50, color=color, ls='dashed', lw=0.5)
      axr.axhline(y=delta_mean, color=color, ls='dotted', lw=0.5)
      total_line += ' %s { avg: %s median: %s stddev: %s }\n' % (
          d,
          decimal_fmt(delta_mean, 'sec'),
          decimal_fmt(delta_quantile_50, 'sec'),
          decimal_fmt(delta_stddev, 'sec'))

    # print a boxplot
    bp_data = [df['delta'] for df in data.values()]
    bp = axl.boxplot(bp_data, sym='k+',
                     notch=True,
                     bootstrap=5000,
                     patch_artist=True)
    if delta == 'delta4':
      axl.set_yscale('log')
      axr.set_yscale('log')

    # change the names of the distro ticks
    plt.setp(axl, xticklabels=data.keys())

    # mark the medians in white
    plt.setp(bp['medians'], color='white')
    # add a mark for the average (mean)
    for i in range(len(data.values())):
      df_local = data.values()[i]
      if len(df_local) == 0:  # pylint: disable=g-explicit-length-test
        continue
      med = bp['medians'][i]
      delta_mean = df_local.delta.mean()
      axl.plot([np.average(med.get_xdata())], [delta_mean],
               color='w', marker='*', markeredgecolor='k')

    i = 0
    for obj in bp['boxes']:
      d = data.keys()[i]
      color, marker = DIR_CONN_COLOR_D[delta][d]
      plt.setp(obj, color=color)
      i += 1
    i = 0
    for obj in bp['whiskers'] + bp['caps']:
      d = data.keys()[(i / 2) % 2]
      color, marker = DIR_CONN_COLOR_D[delta][d]
      plt.setp(obj, color=color, ls='solid', lw=0.5)
      i += 1

    # shift x axis
    min_time_shift = min(time_shift.values())
    format_shift = ticker.FuncFormatter(
        lambda x, pos: '{0:g}'.format(x - min_time_shift))
    axr.xaxis.set_major_formatter(format_shift)

    # plot labels
    axr.set_xlabel('trace timestamp (sec) -- ' + total_line,
                   fontsize='xx-small')
    axl.set_ylabel('%s value (sec)' % delta, fontsize='x-small')
    axl.tick_params(axis='both', which='major', labelsize=10)
    axl.tick_params(axis='both', which='minor', labelsize=8)
    axr.tick_params(axis='both', which='major', labelsize=10)
    axr.tick_params(axis='both', which='minor', labelsize=8)
    return (axl, axr)

  def add_distribution_graph(self, delta, ax, data):
    """Print the time series."""
    for i in range(len(data)):
      df_local = data.values()[i]
      d = data.keys()[i]
      color, _ = DIR_CONN_COLOR_D[delta][d]

      # # 1. print the head distro
      # df_head = df_local[df_local.delta < CUT_VALUE_HEAD_SECS]
      # if len(df_head) >= 1:
      #   n, bins, _ = ax[delta]['head'].hist(df_head.delta.values,
      #                                       NUM_BINS, histtype='step',
      #                                       cumulative=False)
      #   # set the xlim before adding the percentiles
      #   ax[delta]['head'].set_xlim(0, bins[-1])

      # 2. print the tail distro
      _, _, _ = ax.hist(df_local.delta.values, NUM_BINS,
                        histtype='step', cumulative=False,
                        color=color)

      # 3. calculate the delta percentiles
      delta_quantile_50 = df_local.delta.quantile(q=0.50)
      delta_quantile_99 = df_local.delta.quantile(q=0.99)

      # print the delta percentile lines
      ax.axvline(x=delta_quantile_50, color=color, ls='dashed', lw=0.5)
      ax.axvline(x=delta_quantile_99, color=color, ls='dotted', lw=0.5)

    # plot labels
    # ax[delta]['head'].set_xlabel('%s value (sec)' % delta,
    #                              fontsize='xx-small')
    # ax[delta]['head'].set_ylabel('Head PDF (absolute)', fontsize='x-small')
    ax.set_xlabel('%s value (sec)' % delta, fontsize='xx-small')
    ax.set_ylabel('Tail PDF (absolute)', fontsize='x-small')
    ax.tick_params(axis='both', which='major', labelsize=10)
    ax.tick_params(axis='both', which='minor', labelsize=8)

    # # capture up to the n largest bins in the tail
    # if len(np.where(bins > CUT_VALUE_TAIL_SECS)[0]) >= 1:
    #   # trace has packets with delta in the tail
    #   index = np.where(bins > CUT_VALUE_TAIL_SECS)[0][0]
    #   argarray = n[index:].argsort()[-NUM_LARGEST_BINS:]
    #   ymax_remaining = n[index + argarray[-1]]
    #   ax[delta]['tail'].set_ylim(0, ymax_remaining * 1.5)
    #   # add lines for the largest bins
    #   xlist = []
    #   for i in argarray[::-1]:
    #     yval = n[index + i]
    #     xval = bins[index + i]
    #     # discard values too close to previous values
    #     if any([abs(x - xval) < MIN_SEPARATION for x in xlist]):
    #       continue
    #     xlist += [xval]
    #     ax[delta]['tail'].axvline(x=xval, color='r', ls='dotted')
    #     ax[delta]['tail'].text(xval, yval,
    #                            'delta: %s' % decimal_fmt(xval, 'sec'),
    #                            fontsize='x-small')
    #     ax[delta]['time'].axhline(y=xval, color='r', ls='dotted')

    # # print the min_delta(pkt_len) distribution
    # tcp_len_list = df_local.tcp_len.unique()
    # tcp_len_list.sort()
    # delta_list = []
    # for tcp_len in tcp_len_list:
    #   delta_list.append(min(df_local[df_local.tcp_len == tcp_len].delta))
    # ax[delta]['length'].loglog(tcp_len_list, delta_list,
    #                            linestyle='', marker='x',
    #                            color=color, markersize=3)
    # ax[delta]['length'].axhline(y=delta_min, color=color, ls='dotted')

    # # plot labels
    # ax[delta]['length'].set_xlabel('Packet size (bytes)',
    #                                fontsize='x-small')
    # ax[delta]['length'].set_ylabel('min %s time (secs)' % delta,
    #                                fontsize='x-small')

  def get_most_popular_connections(self, df, delta, max_conn):
    """Select the `max_conn` most popular connections based on `delta`."""
    separate_conn_l = []
    i = 0
    df_all = df
    for i in range(max_conn):
      if len(df_all) < 1:
        break
      order = df_all[delta].argmax()
      src = df_all.src[order]
      dst = df_all.dst[order]
      try:
        color, marker = IP_CONN_COLOR_D[i]
      except KeyError:
        color, marker = IP_CONN_COLOR_D['remaining']
      separate_conn_l += [[src, dst, color, marker]]
      # remove the connection
      df_all = df_all[(df_all.src != src) | (df_all.dst != dst)]
      i += 1
    return separate_conn_l
