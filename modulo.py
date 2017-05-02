#!/usr/bin/python

"""Modulo number operations."""


class Modulo(object):
  """A class providing modulo math operations."""

  def __init__(self, max_value, invalid=-1):
    self._max = max_value
    self._half_max = self._max >> 1
    self._invalid = invalid

  def wrap_correction(self, x):
    """Returns x in the range [0..self._max]."""
    return ((x % (self._max + 1)) + (self._max + 1)) % (self._max + 1)

  def add(self, x, y):
    """Returns (x+y) in the range [0..self._max]."""
    if x == self._invalid or y == self._invalid:
      return self._invalid
    return self.wrap_correction(x + y)

  def diff(self, x, y):
    """Returns (x-y) in the range [-self._half_max..self._half_max]."""
    if x == self._invalid or y == self._invalid:
      return self._invalid
    return self.wrap_correction(x - y)

  def sub(self, x, y):
    """Returns (x-y) in the range [0..self._max]."""
    if x == self._invalid or y == self._invalid:
      return self._invalid
    diff = self.wrap_correction(x - y)
    if diff > ((self._max + 1) >> 1):
      return diff - (self._max + 1)
    return diff

  def cmp(self, x, y):
    """Compares 2 values.

    Args:
      x: first value
      y: second value

    Returns:
      an integer less than, equal to, or greater than zero if x is
      found, respectively, to be less than, to match, or be greater than y.
    """
    diff = self.wrap_correction(y - x)
    if diff == 0:
      # y - x == 0
      return 0
    elif diff > ((self._max + 1) >> 1):
      # y - x < 0
      return 1
    else:
      # y - x > 0
      return -1

  def cmp_range_closed(self, x, y1, y2):
    """Compares a value and a range [y1, y2].

    Args:
      x: value to compare
      y1: start of the range
      y2: end of the range

    Returns:
      an integer less than, equal to, or greater than zero if x is found,
      respectively, to be less than y1, in [y1, y2], or greater than y2.
    """
    if self.cmp(x, y1) < 0:
      # x < y1
      return -1
    elif self.cmp(x, y1) >= 0 and self.cmp(x, y2) <= 0:
      # y1 <= x <= y2
      return 0
    else:
      # y2 < x
      return 1

  def cmp_range_closed_open(self, x, y1, y2):
    """Compares a value and a range [y1, y2).

    Args:
      x: value to compare
      y1: start of the range
      y2: end of the range

    Returns:
      an integer less than, equal to, or greater than zero if x is found,
      respectively, to be less than y1, in [y1, y2), or greater or equal to y2.
    """
    if self.cmp(x, y1) < 0:
      # x < y1
      return -1
    elif self.cmp(x, y1) >= 0 and self.cmp(x, y2) < 0:
      # y1 <= x < y2
      return 0
    else:
      # y2 <= x
      return 1

  def range_overlap(self, x1, x2, y1, y2):
    """Whether the ranges ([x1, x2] and [y1, y2]) overlap at all."""
    if self.cmp(y2, x1) < 0 or self.cmp(y1, x2) > 0:
      return False
    return True

  def max(self, x, y):
    """Returns the greatest of 2 values."""
    if x == self._invalid:
      return y
    if y == self._invalid:
      return x
    if self.cmp(x, y) < 0:
      return y
    return x

  def map_into_same_timeline(self, x, ref_value):
    """Map a value on the same timeline than a reference one.

    Map a value x into the same time line as a reference value in order
    to compare them easily.
    A timeline is essentially one "run" from 0 to self._max. If two
    values are separated by a wrap-around point, they are in two
    different timelines and cannot be compared directly.
    Note that the values cannot be apart by more self._half_max or else
    it is not possible to correctly map them (aliasing effect).

    Args:
      x: value to map
      ref_value: reference value

    Returns:
      the mapped value. In most cases (both are on the same
      timeline) it will be the same as the input value, but in the wrapped
      case, the mapped value may be negative or larger than self._max.
    """
    # The two values have a wrapping point between them if they are more
    # than self._half_max apart.
    if x > ref_value + self._half_max:
      # target -> wrap-point -> ref
      return x - (self._max + 1)
    elif ref_value > x + self._half_max:
      # ref -> wrap-point -> target
      return x + (self._max + 1)
    return x
