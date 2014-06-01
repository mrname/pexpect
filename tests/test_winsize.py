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
import time

class TestCaseWinsize(PexpectTestCase.PexpectTestCase):

    def test_getwinsize(self):
        """ Default winsize should be 24x80. """
        # given,
        child = pexpect.spawn('cat')
        want_rows, want_cols = 24, 80

        # exercise,
        try:
            def_rows, def_cols = child.getwinsize()
        except OSError as err:
            if err.args[0] == 22:
                self.assertTrue(err.args[1].startswith(
                    'Invalid argument: getwinsize() may not be '
                    'called on this platform'))
                raise unittest.SkipTest("getwinsize() not supported")
            raise

        # verify,
        self.assertEqual((def_rows, def_cols), (want_rows, want_cols))

    def _setwinsize(self, rows, cols):
        """ Child process should receive sigwinch on TIOCSWINSZ. """
        # given,
        child = pexpect.spawn('%s sigwinch_report.py' % self.PYTHONBIN)
        want_rows, want_cols = rows, cols
        re_sigwinch = b'SIGWINCH: \(([0-9]*), ([0-9]*)\)'
        table = [pexpect.TIMEOUT, re_sigwinch,]
        want_index = table.index(re_sigwinch)
        time_index = table.index(pexpect.TIMEOUT)

        # exercise,
        child.expect('READY', timeout=5)
        child.setwinsize (want_rows, want_cols)
        index = child.expect(table, timeout=5)

        # verify,
        if index == time_index:
            raise unittest.SkipTest("this platform may not support sigwinch")

        self.assertEqual(index == want_index)
        got_rows, got_cols = map(int, child.match.group(1, 2))
        self.assertEqual((got_rows, got_cols), (want_rows, want_cols))

    def test_setwinsize_11_22(self):
        """ Test child process accepts SIGWINCH for window size 11x22. """
        self._setwinsize(11, 22)


if __name__ == '__main__':
    unittest.main()

suite = unittest.makeSuite(TestCaseWinsize, 'test')
