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
from __future__ import print_function

import pexpect
import unittest
import PexpectTestCase
import string
import sys

if sys.version_info[0] >= 3:
    def byte(i):
        return bytes([i])
else:
    byte = chr


class TestCtrlChars(PexpectTestCase.PexpectTestCase):
    sent = []

    def test_sendintr(self):
        " Test Ctrl-C. "
        child = pexpect.spawn('python getch.py')
        child.expect('READY', timeout=5)
        child.sendintr()
        child.expect('3\r\n')

        self._goodbye(child)

    def test_sendeof(self):
        " Test Ctrl-D. "
        child = pexpect.spawn('python getch.py')
        child.expect('READY', timeout=5)
        child.sendeof()
        child.expect('4\r\n')

        self._goodbye(child)

    def test_bad_sendcontrol_chars (self):
        '''This tests that sendcontrol will return 0 for an unknown char. '''
        child = pexpect.spawn('cat')
        # there is no such thing as ctrl-1.
        self.assertEqual(0, child.sendcontrol('1'))

    def test_sendcontrol(self):
        '''This tests that we can send all special control codes by name.
        '''
        child = pexpect.spawn('python getch.py')

        # On slow machines, like Travis, the process is not ready in time to
        # catch the first character unless we wait for it.
        child.expect('READY', timeout=5)
        child.delaybeforesend = 0.05
        for ctrl in string.ascii_lowercase:
            self.assertEqual(1, child.sendcontrol(ctrl))
            exp_val = '%s\r\n' % (ord(ctrl) - ord('a') + 1,)
            self.sent.append(int(exp_val.rstrip()))
            child.expect_exact(exp_val, timeout=3)

        # escape character
        self.assertEqual(1, child.sendcontrol('['))
        self.sent.append(27)
        child.expect('27\r\n')

        self.assertEqual(1, child.sendcontrol('\\'))
        self.sent.append(28)
        child.expect('28\r\n')

        # telnet escape character
        self.assertEqual(1, child.sendcontrol(']'))
        self.sent.append(29)
        child.expect('29\r\n')

        self.assertEqual(1, child.sendcontrol('^'))
        self.sent.append(30)
        child.expect('30\r\n')

        # irc protocol uses this to underline ...
        self.assertEqual(1, child.sendcontrol('_'))
        self.sent.append(31)
        child.expect('31\r\n')

        # the real "backspace is delete"
        self.assertEqual(1, child.sendcontrol('?'))
        self.sent.append(127)
        child.expect('127\r\n')

        self._goodbye(child)

    def test_control_chars(self):
        ' Test all (remaining) 8-bit chracters '
        child = pexpect.spawn('python getch.py')
        child.expect('READY', timeout=5)
        for ival in filter(lambda i: i not in self.sent, range(1, 256)):
            child.send(byte(ival))
            child.expect('%d\r\n' % (ival,))

        self._goodbye(child)

    def _goodbye(self, child):
        # NUL, same as ctrl + ' '
        self.assertEqual(1, child.sendcontrol('@'))
        self.sent.append(0)
        child.expect('0\r\n')

        # 0 is sentinel value to getch.py, assert exit
        child.expect(pexpect.EOF)
        self.assertEqual(False, child.isalive())
        self.assertEqual(0, child.exitstatus)

if __name__ == '__main__':
    unittest.main()

suite = unittest.makeSuite(TestCtrlChars, 'test')
