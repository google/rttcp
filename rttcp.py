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


"""Simple tcp flow aggregation."""


import argparse
import os.path
import sys

from common import __version__
from packet_dumper import PacketDumper
from plotter import Plotter


def get_options(argv):
  """Generic option parser.

  Args:
    argv: list containing arguments

  Returns:
    argparse.ArgumentParser - generated option object
  """
  # init parser
  parser = argparse.ArgumentParser(description='rttcp flow aggregator.')
  subparsers = parser.add_subparsers()
  # independent sub-commands
  parser_help = subparsers.add_parser('help', help='show help screen')
  parser_help.set_defaults(subcommand='help')
  parser_anal = subparsers.add_parser('analyze', help='analyze pcap file')
  parser_anal.set_defaults(subcommand='analyze')
  parser_plot = subparsers.add_parser('plot', help='plot analysis file')
  parser_plot.set_defaults(subcommand='plot')
  # common arguments
  for p in (parser, parser_anal, parser_plot):
    p.add_argument('-d', '--debug', action='count',
                   dest='debug', default=0,
                   help='Increase verbosity (use multiple times for more)',)
    p.add_argument('--quiet', action='store_const',
                   dest='debug', const=-1,
                   help='Zero verbosity',)
    p.add_argument('-v', '--version', action='version',
                   version=__version__)
    p.add_argument('--tshark', dest='tshark',
                   default='tshark',
                   metavar='TSHARK',
                   help='tshark binary',)
    p.add_argument('-i', '--input', dest='infile', default=None,
                   metavar='INPUT-FILE',
                   help='input file',)
    p.add_argument('-o', '--output', dest='outfile', default=None,
                   metavar='OUTPUT-FILE',
                   help='output file',)
    p.add_argument('--type', action='store',
                   dest='analysis_type', default='flow',
                   metavar='ANALYSIS_TYPE',
                   help='set the analysis type (flow, packet)')
    p.add_argument('--src-reverse', dest='src_reverse', default=None,
                   metavar='SRC-REVERSE',
                   help='any packet from a src definition (cidr) as reverse',)
  # plot-only arguments
  parser_plot.add_argument('--title', action='store',
                           dest='plot_title', default='',
                           metavar='PLOT_TITLE',
                           help='set the plot title')
  parser_plot.add_argument('--format', action='store',
                           dest='plot_format', default='pdf',
                           metavar='PLOT_FORMAT',
                           help='set the plot format')
  # do the parsing
  options = parser.parse_args(argv[1:])
  if options.subcommand == 'help':
    parser.print_help()
    sys.exit(0)
  return options


def main(argv):
  # parse options
  options = get_options(argv)
  # get infile/outfile
  if options.infile in (None, '-'):
    options.infile = sys.stdin
  else:
    # ensure file exists
    assert os.path.isfile(options.infile), (
        'File %s does not exist' % options.infile)
  if options.outfile in (None, '-'):
    options.outfile = sys.stdout
  # print results
  if options.debug > 0:
    sys.stderr.write('%s\n' % options)
  # do something
  if options.subcommand == 'analyze':
    packet_dumper = PacketDumper(options.tshark,
                                 options.infile,
                                 options.outfile,
                                 options.analysis_type,
                                 options.debug)
    packet_dumper.run()

  elif options.subcommand == 'plot':
    plotter = Plotter(options.infile,
                      options.outfile,
                      options.analysis_type,
                      options.plot_format,
                      options.plot_title,
                      options.src_reverse,
                      options.debug)
    plotter.run()


if __name__ == '__main__':
  main(sys.argv)
