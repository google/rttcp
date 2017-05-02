#!/usr/bin/python

"""Unit tests for modulo.py."""

import unittest
from modulo import Modulo


class ModuloTest(unittest.TestCase):

  MAX_VALUE = (1 << 33) - 1
  HALF_MAX_VALUE = MAX_VALUE >> 1
  INVALID_VALUE = -1

  def testWrapCorrection(self):
    """A test of the wrap_correction() method."""
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.wrap_correction(0))
    self.assertEqual(90000, m.wrap_correction(90000))
    self.assertEqual(0, m.wrap_correction(self.MAX_VALUE + 1))
    self.assertEqual(90000, m.wrap_correction(self.MAX_VALUE + 1 + 90000))
    self.assertEqual(self.MAX_VALUE, m.wrap_correction(self.INVALID_VALUE))
    self.assertEqual(self.MAX_VALUE - 1, m.wrap_correction(-2))
    self.assertEqual(0, m.wrap_correction(2 * (self.MAX_VALUE + 1) + 0))
    self.assertEqual(1, m.wrap_correction(3 * (self.MAX_VALUE + 1) + 1))
    self.assertEqual(0, m.wrap_correction(-self.MAX_VALUE - 1))
    self.assertEqual(0, m.wrap_correction(-(2 * (self.MAX_VALUE + 1)) + 0))
    self.assertEqual(1, m.wrap_correction(-(3 * (self.MAX_VALUE + 1)) + 1))

  def testCmp(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.cmp(0, 0))
    self.assertEqual(0, m.cmp(0, self.MAX_VALUE + 1))
    self.assertEqual(0, m.cmp(90000, self.MAX_VALUE + 1 + 90000))
    self.assertEqual(-1, m.cmp(0, 1))
    self.assertEqual(1, m.cmp(1, 0))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE, 0))
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE))
    self.assertEqual(-1, m.cmp(0, (self.MAX_VALUE + 1) >> 1))
    self.assertEqual(1, m.cmp(0, ((self.MAX_VALUE + 1) >> 1) + 1))

  def testCmpRangeClosed(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(-1, m.cmp_range_closed(89999, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed(90000, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed(90001, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed(90999, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed(91000, 90000, 91000))
    self.assertEqual(1, m.cmp_range_closed(91001, 90000, 91000))
    self.assertEqual(-1, m.cmp_range_closed(self.MAX_VALUE, 0, 1))
    self.assertEqual(0, m.cmp_range_closed(0, 0, 1))
    self.assertEqual(0, m.cmp_range_closed(1, 0, 1))
    self.assertEqual(1, m.cmp_range_closed(2, 0, 1))
    self.assertEqual(1, m.cmp_range_closed(((self.MAX_VALUE + 1) >> 1) - 1,
                                           0, 1))
    self.assertEqual(-1, m.cmp_range_closed((self.MAX_VALUE + 1) >> 1, 0, 1))

  def testCmpRangeClosedOpen(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(-1, m.cmp_range_closed_open(89999, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed_open(90000, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed_open(90001, 90000, 91000))
    self.assertEqual(0, m.cmp_range_closed_open(90999, 90000, 91000))
    self.assertEqual(1, m.cmp_range_closed_open(91000, 90000, 91000))
    self.assertEqual(1, m.cmp_range_closed_open(91001, 90000, 91000))
    self.assertEqual(-1, m.cmp_range_closed_open(self.MAX_VALUE, 0, 1))
    self.assertEqual(0, m.cmp_range_closed_open(0, 0, 1))
    self.assertEqual(1, m.cmp_range_closed_open(1, 0, 1))
    self.assertEqual(1, m.cmp_range_closed_open(2, 0, 1))
    self.assertEqual(1, m.cmp_range_closed_open(
        ((self.MAX_VALUE + 1) >> 1) - 1, 0, 1))
    self.assertEqual(-1, m.cmp_range_closed_open((self.MAX_VALUE + 1) >> 1,
                                                 0, 1))

  def testRangeOverlap(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    y1 = 1000
    y2 = 2000
    test_arr = [
        # [x1, x2] covers [y1, y2]
        [0, 4000, True],
        [1000, 2000, True],
        [999, 2000, True],
        [1000, 2001, True],
        [999, 2001, True],
        # [x1, x2] is covered by [y1, y2]
        [1001, 1999, True],
        [1500, 1501, True],
        # y1 is overlapped
        [900, 1500, True],
        # y2 is overlapped
        [1500, 2100, True],
        # non overlap
        [900, 999, False],
        [2001, 2100, False],
    ]
    for item in test_arr:
      x1, x2, expected_overlap = item
      self.assertEqual(expected_overlap, m.range_overlap(x1, x2, y1, y2))
      # overlap is a commutative operation
      self.assertEqual(expected_overlap, m.range_overlap(y1, y2, x1, x2))

  def testAdd(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.add(0, 0))
    self.assertEqual(123, m.add(23, 100))
    self.assertEqual(100, m.add(-100, 200))
    self.assertEqual(self.INVALID_VALUE, m.add(self.INVALID_VALUE, 100))
    self.assertEqual(self.INVALID_VALUE, m.add(100, self.INVALID_VALUE))
    self.assertEqual(self.INVALID_VALUE, m.add(self.INVALID_VALUE,
                                               self.INVALID_VALUE))

  def testDiff(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.diff(0, 0))
    self.assertEqual(23, m.diff(123, 100))
    self.assertEqual(self.MAX_VALUE + 1 - 23, m.diff(100, 123))
    self.assertEqual(123456, m.diff(self.MAX_VALUE, self.MAX_VALUE - 123456))
    self.assertEqual(self.MAX_VALUE+1-123456,
                     m.diff(self.MAX_VALUE - 123456, self.MAX_VALUE))
    self.assertEqual(9, m.diff(m.wrap_correction(self.MAX_VALUE + 9),
                               self.MAX_VALUE))
    self.assertEqual(self.MAX_VALUE+1-9,
                     m.diff(self.MAX_VALUE,
                            m.wrap_correction(self.MAX_VALUE + 9)))
    self.assertEqual(16234, m.diff(15000, m.wrap_correction(-1234)))
    self.assertEqual(self.HALF_MAX_VALUE,
                     m.diff(self.HALF_MAX_VALUE, 0))
    self.assertEqual(self.MAX_VALUE + 1 - self.HALF_MAX_VALUE,
                     m.diff(0, self.HALF_MAX_VALUE))
    self.assertEqual(self.INVALID_VALUE, m.diff(self.INVALID_VALUE, 100))
    self.assertEqual(self.INVALID_VALUE, m.diff(100, self.INVALID_VALUE))
    self.assertEqual(self.INVALID_VALUE,
                     m.diff(self.INVALID_VALUE, self.INVALID_VALUE))

  def testSub(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.sub(0, 0))
    self.assertEqual(23, m.sub(123, 100))
    self.assertEqual(-23, m.sub(100, 123))
    self.assertEqual(123456,
                     m.sub(self.MAX_VALUE, self.MAX_VALUE - 123456))
    self.assertEqual(-123456,
                     m.sub(self.MAX_VALUE - 123456, self.MAX_VALUE))
    self.assertEqual(9, m.sub(m.wrap_correction(self.MAX_VALUE + 9),
                              self.MAX_VALUE))
    self.assertEqual(-9, m.sub(self.MAX_VALUE,
                               m.wrap_correction(self.MAX_VALUE + 9)))
    self.assertEqual(16234, m.sub(15000, m.wrap_correction(-1234)))
    self.assertEqual(self.HALF_MAX_VALUE,
                     m.sub(self.HALF_MAX_VALUE, 0))
    self.assertEqual(-self.HALF_MAX_VALUE,
                     m.sub(0, self.HALF_MAX_VALUE))
    self.assertEqual(self.INVALID_VALUE, m.sub(self.INVALID_VALUE, 100))
    self.assertEqual(self.INVALID_VALUE, m.sub(100, self.INVALID_VALUE))
    self.assertEqual(self.INVALID_VALUE,
                     m.sub(self.INVALID_VALUE, self.INVALID_VALUE))

  def testCompareEq(self):
    # Compare same value
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    self.assertEqual(0, m.cmp(0, 0))
    self.assertEqual(0, m.cmp(10, 10))
    self.assertEqual(0, m.cmp(3423410, 3423410))
    self.assertEqual(0, m.cmp(898798798, 898798798))
    self.assertEqual(0, m.cmp(self.MAX_VALUE, self.MAX_VALUE))

  def testCompareLarger(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    # first value larger than second by 1
    self.assertEqual(1, m.cmp(1, 0))
    self.assertEqual(1, m.cmp(10, 9))
    self.assertEqual(1, m.cmp(3423410, 3423409))
    self.assertEqual(1, m.cmp(898798798, 898798797))
    self.assertEqual(1, m.cmp(self.MAX_VALUE, self.MAX_VALUE - 1))
    # first value larger than second by a lot
    self.assertEqual(1, m.cmp(10, 5))
    self.assertEqual(1, m.cmp(3423410, 342340))
    self.assertEqual(1, m.cmp(898798798, 689879877))
    self.assertEqual(1, m.cmp(self.MAX_VALUE, self.MAX_VALUE - 110000))

  def testCompareSmaller(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    # first value smaller than second by 1
    self.assertEqual(-1, m.cmp(0, 1))
    self.assertEqual(-1, m.cmp(10, 11))
    self.assertEqual(-1, m.cmp(3423410, 3423411))
    self.assertEqual(-1, m.cmp(898798798, 898798799))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1, self.MAX_VALUE))
    # first value smaller than second by a lot
    self.assertEqual(-1, m.cmp(0, 1000))
    self.assertEqual(-1, m.cmp(10, 11000))
    self.assertEqual(-1, m.cmp(423410, 3423411))
    self.assertEqual(-1, m.cmp(498798798, 898798799))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 100000, self.MAX_VALUE))

  def testCompareWrapSmaller(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    # first value smaller than second with wrap around
    # Test edge limit on the 1st value
    self.assertEqual(-1, m.cmp(self.MAX_VALUE, 0))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE, 1))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE, 1100))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE, 99999))

    # Test edge limit on the 2nd value
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1, 0))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 2, 0))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1000, 0))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 9999, 0))

    # Test close to edge limit on the 2nd value
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1, 1))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 2, 1))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1000, 1))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 9999, 1))

    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1, 134234))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 2, 43213123))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 1000, 212321))
    self.assertEqual(-1, m.cmp(self.MAX_VALUE - 9999, 7842341))

  def testCompareWrapBigger(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    # first value bigger than second with wrap around
    # Test edge limit on the 2nd value
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE))
    self.assertEqual(1, m.cmp(1, self.MAX_VALUE))
    self.assertEqual(1, m.cmp(1100, self.MAX_VALUE))
    self.assertEqual(1, m.cmp(999999, self.MAX_VALUE))

    # Test edge limit on the first value
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE - 1))
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE - 2))
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE - 1000))
    self.assertEqual(1, m.cmp(0, self.MAX_VALUE - 9999))

    # Test close to edge limit on the first value
    self.assertEqual(1, m.cmp(1, self.MAX_VALUE - 1))
    self.assertEqual(1, m.cmp(1, self.MAX_VALUE - 2))
    self.assertEqual(1, m.cmp(1, self.MAX_VALUE - 1000))
    self.assertEqual(1, m.cmp(1, self.MAX_VALUE - 9999))

    self.assertEqual(1, m.cmp(13434, self.MAX_VALUE - 1))
    self.assertEqual(1, m.cmp(134234234, self.MAX_VALUE - 2))
    self.assertEqual(1, m.cmp(342341, self.MAX_VALUE - 1000))
    self.assertEqual(1, m.cmp(743451, self.MAX_VALUE - 9999))

  def testMapIntoSameTimeline(self):
    m = Modulo(self.MAX_VALUE, self.INVALID_VALUE)
    x_list = [
        -self.HALF_MAX_VALUE, -self.HALF_MAX_VALUE + 1,
        -self.HALF_MAX_VALUE + 3, -self.HALF_MAX_VALUE / 2,
        -self.HALF_MAX_VALUE / 4, -self.HALF_MAX_VALUE / 8,
        -256, -100, -10, -3, -1, 0, 1, 3, 10, 100, 256,
        self.HALF_MAX_VALUE / 8, self.HALF_MAX_VALUE / 4,
        self.HALF_MAX_VALUE / 2, self.HALF_MAX_VALUE - 3,
        self.HALF_MAX_VALUE - 1, self.HALF_MAX_VALUE,
    ]
    ref_list = [
        0, 1, 3, 10, 100, 256,
        self.MAX_VALUE/16-1, self.MAX_VALUE/16, self.MAX_VALUE/16+1,
        self.MAX_VALUE/8-1, self.MAX_VALUE/8, self.MAX_VALUE/8+1,
        self.MAX_VALUE/4-1, self.MAX_VALUE/4, self.MAX_VALUE/4+1,
        self.MAX_VALUE/2-1, self.MAX_VALUE/2, self.MAX_VALUE/2+1,
        self.MAX_VALUE-1, self.MAX_VALUE,
    ]

    for r in ref_list:
      for x in x_list:
        v = m.wrap_correction(r + x)
        self.assertGreaterEqual(v, 0)
        self.assertLessEqual(v, self.MAX_VALUE)
        mapped_value = m.map_into_same_timeline(v, r)
        self.assertEqual(r + x, mapped_value)


if __name__ == '__main__':
  unittest.main()

