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


"""Common code."""


__version__ = '0.0.1'

TCP_SEQ_MAX_VALUE = (1 << 33) - 1


def endpoint_cmp(ip1, port1, ip2, port2):
  if ip1 < ip2:
    return -1
  if ip1 > ip2:
    return 1
  return cmp(port1, port2)


# http://stackoverflow.com/questions/1094841/
def binary_fmt(num, suffix='B'):
  """A binary pretty-printer."""
  if num == 0.0:
    return '0 %s' % suffix
  for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
    if abs(num) < 1024.0:
      return '%.3g %s%s' % (num, unit, suffix)
    num /= 1024.0
  return '%.3g %s%s' % (num, 'Yi', suffix)


def decimal_fmt(num, suffix='sec'):
  """A decimal pretty-printer."""
  if num == 0.0:
    return '0 %s' % suffix
  if num < 1.0:
    for unit in ['', 'm', 'u', 'n', 'p', 'f', 'a', 'z']:
      if abs(num) >= 1.0:
        return '%.3g %s%s' % (num, unit, suffix)
      num *= 1000.0
    return '%.3g %s%s' % (num, 'y', suffix)
  for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
    if abs(num) < 1000.0:
      return '%.3g %s%s' % (num, unit, suffix)
    num /= 1000.0
  return '%.3g %s%s' % (num, 'Y', suffix)

