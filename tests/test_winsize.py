#!/usr/bin/env python
'''
PEXPECT LICENSE

    This license is approved by the OSI and FSF as GPL-compatible.
        http://opensource.org/licenses/isc-license.txt

    Copyright (c) 2012, Noah Spurrier <noah@noah.org>
    PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY
    PURPOSE WITH OR WITHOUT FEE IS HEREBY GRANTED, PROVIDED THAT THE ABOVE
    COPYRIGHT NOTICE AND THIS PERMISSION NOTICE APPEAR IN ALL COPIES.
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

'''
import pexpect
import unittest
import PexpectTestCase


class TestCaseWinsize(PexpectTestCase.PexpectTestCase):

    def _getwinsize(self, rows, cols):
        """ getwinsize provides want_rows & _cols """
        # given,
        child = pexpect.spawn('cat')

        # exercise,
        try:
            got_rows, got_cols = child.getwinsize()
        except OSError as err:
            if err.args[0] == 22:
                self.assertTrue(err.args[1].endswith(
                    ': getwinsize() may not be called on this platform'))
                if hasattr(unittest, 'SkipTest'):
                    raise unittest.SkipTest("getwinsize() not supported")
                else:
                    return "SKIP"
            raise

        # verify,
        self.assertEqual((got_rows, got_cols), (rows, cols))

    def _setwinsize(self, rows, cols):
        """ child process receives rows, cols. """
        # given,
        child = pexpect.spawn('%s sigwinch_report.py' % self.PYTHONBIN)
        re_sigwinch = b'SIGWINCH: \(([0-9]*), ([0-9]*)\)'
        table = [pexpect.TIMEOUT, re_sigwinch,]
        want_index = table.index(re_sigwinch)
        time_index = table.index(pexpect.TIMEOUT)

        # exercise,
        child.expect('READY', timeout=5)
        child.setwinsize (rows, cols)
        index = child.expect(table, timeout=5)

        # skip,
        if index == time_index:
            if hasattr(unittest, 'SkipTest'):
                raise unittest.SkipTest("setwinsize() not supported")
            else:
                return "SKIP"

        # verify,
        self.assertEqual(index, want_index)
        got_rows, got_cols = map(int, child.match.group(1, 2))
        self.assertEqual((got_rows, got_cols), (rows, cols))

    def test_default_winsize_24_80(self):
        self._getwinsize(24, 80)

    def test_setwinsize_11_22(self):
        """ Test child process accepts SIGWINCH for window size 11x22. """
        self._setwinsize(11, 22)

    def test_set_then_getwinsize_11_22(self):
        """ Test child process accepts SIGWINCH for window size 11x22. """
        self._setwinsize(11, 22)

        try:
            self._getwinsize(11, 22)
        except AssertionError as err:
            # Fascinating. Returns (80, 24) on OSX
            if str(err).startswith("Tuples differ"):
                if hasattr(unittest, 'SkipTest'):
                    raise unittest.SkipTest("getwinsize() cannot read child's "
                                            "size on this platform.")
                else:
                    return "SKIP"
            elif str(err).startswith("(24, 80) !="):
                # python2.6
                return "SKIP"
            raise

if __name__ == '__main__':
    unittest.main()

suite = unittest.makeSuite(TestCaseWinsize, 'test')
