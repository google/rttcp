#!/usr/bin/python

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

