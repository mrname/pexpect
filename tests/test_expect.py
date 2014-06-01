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
from __future__ import with_statement  # bring 'with' stmt to py25
import pexpect
import unittest
import subprocess
import time
import PexpectTestCase
import signal

FILTER=''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])


def hex_dump(src, length=16):
    result = []
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %-*s   %s\n" % (i, length*3, hexa, printable))
    return ''.join(result)


def hex_diff(left, right):
        diff = ['< %s\n> %s' % (_left, _right,) for _left, _right in zip(
            hex_dump(left).splitlines(), hex_dump(right).splitlines())
            if _left != _right]
        return '\n' + '\n'.join(diff,)


class assert_raises_msg(object):
    def __init__(self, errtype, msgpart):
        self.errtype = errtype
        self.msgpart = msgpart

    def __enter__(self):
        pass

    def __exit__(self, etype, value, traceback):
        if value is None:
            raise AssertionError('Expected %s, but no exception was raised'
                                 % self.errtype)
        if not isinstance(value, self.errtype):
            raise AssertionError('Expected %s, but %s was raised'
                                 % (self.errtype, etype))

        errstr = str(value)
        if self.msgpart not in errstr:
            raise AssertionError('%r was not in %r' % (self.msgpart, errstr))

        return True


class ExpectTestCase (PexpectTestCase.PexpectTestCase):

    def _goodbye_cat(self, child):
        child.sendeof()
        child.expect(pexpect.EOF)
        self.assertFalse(child.isalive())
        self.assertEqual(0, child.exitstatus)

    def _send_123(self, child):
        child.sendline(b'ONE')
        child.sendline(b'TWO')
        child.sendline(b'THREE')

    def test_expect_basic(self):
        p = pexpect.spawn('cat')
        self._send_123(p)
        p.expect(b'ONE')
        p.expect(b'TWO')
        p.expect(b'THREE')
        self._goodbye_cat(p)

    def test_expect_exact_basic(self):
        p = pexpect.spawn('cat')
        self._send_123(p)
        p.expect_exact(b'ONE')
        p.expect_exact(b'TWO')
        p.expect_exact(b'THREE')
        self._goodbye_cat(p)

    def test_expect_ignore_case(self):
        '''This test that the ignorecase flag will match patterns
        even if case is different using the regex (?i) directive.
        '''
        p = pexpect.spawn('cat')
        self._send_123(p)
        p.expect(b'(?i)oNe')
        p.expect(b'(?i)tWo')
        p.expect(b'(?i)tHrEe')
        self._goodbye_cat(p)

    def test_expect_ignore_case_flag(self):
        '''This test that the ignorecase flag will match patterns
        even if case is different using the ignorecase flag.
        '''
        p = pexpect.spawn('cat')
        self._send_123(p)
        p.ignorecase = True
        p.expect(b'oNe')
        p.expect(b'tWo')
        p.expect(b'tHrEe')
        self._goodbye_cat(p)

    def test_expect_order(self):
        '''This tests priority-order matching of expect method.'''
        p = pexpect.spawn('cat', echo=False)
        self._expect_order(p)

    def test_expect_order_exact(self):
        '''Like test_expect_order(), but using expect_exact().'''
        p = pexpect.spawn('cat', echo=False)
        p.expect = p.expect_exact
        self._expect_order(p)

    def _expect_order (self, p):
        (ONE, TWO, THREE, FOUR, JUNK) = (
            b'alpha', b'beta', b'gamma', b'delta', b'epsilon', )
        map(p.sendline, (ONE, TWO, THREE, FOUR,))
        p.sendeof()

        table = [ONE, TWO, THREE, pexpect.EOF, FOUR, ]
        #        ^
        want_index = table.index(ONE)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

        table = [JUNK, pexpect.TIMEOUT, ONE, TWO, THREE, pexpect.EOF, ]
        #                                    ^
        want_index = table.index(TWO)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

        table = [JUNK, pexpect.TIMEOUT, ONE, TWO, THREE, pexpect.EOF, ]
        #                                         ^
        want_index = table.index(THREE)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

        table = [pexpect.EOF, TWO, THREE, FOUR, ]
        #                                 ^
        want_index = table.index(FOUR)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

        table = [TWO, THREE, FOUR, pexpect.EOF]
        #                          ^
        want_index = table.index(pexpect.EOF)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

        # it is possible to re-expect EOF multiple times
        want_index = table.index(pexpect.EOF)
        index = p.expect(table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

    def test_waitnoecho(self):

        ''' This tests that we can wait on a child process to set echo mode.
        For example, this tests that we could wait for SSH to set ECHO False
        when asking of a password. This makes use of an external script
        echo_wait.py. '''

        p1 = pexpect.spawn('%s echo_wait.py' % self.PYTHONBIN)
        start = time.time()
        try:
            p1.waitnoecho(timeout=10)
        except OSError as err:
            if err.args[0] == 22:
                self.assertTrue(err.args[1].startswith(
                    'Invalid argument: getecho() may not be '
                    'called on this platform'))
                raise unittest.SkipTest("waitnoecho not supported")
            raise

        end_time = time.time() - start
        self.assertTrue(end_time < 10 and end_time > 2,
                        "did not ECHO off in expected time window.")

    def test_waitnoecho_default_timeout(self):
        ' This one is mainly here to test default timeout for code coverage. '
        p1 = pexpect.spawn('%s echo_wait.py' % self.PYTHONBIN)
        start = time.time()
        try:
            p1.waitnoecho()
        except OSError as err:
            if err.args[0] == 22:
                self.assertTrue(err.args[1].startswith(
                    'Invalid argument: getecho() may not be '
                    'called on this platform'))
                raise unittest.SkipTest("waitnoecho not supported")
            raise

        end_time = time.time() - start
        self.assertTrue(end_time < 10 and end_time > 2,
                        "did not ECHO off in expected time window.")

    def test_waitnoecho_cat(self):
        ' test timeout if ECHO is never set off. '
        p1 = pexpect.spawn('cat')
        start = time.time()
        try:
            retval = p1.waitnoecho(timeout=4)
        except OSError as err:
            if err.args[0] == 22:
                self.assertTrue(err.args[1].startswith(
                    'Invalid argument: getecho() may not be '
                    'called on this platform'))
                raise unittest.SkipTest("waitnoecho not supported")
            raise

        self.assertFalse(retval)
        end_time = time.time() - start
        self.assertTrue(end_time > 3,
                        "waitnoecho should have waiting for full timeout.")

    def test_expect_echo(self):
        '''This tests that echo can be turned on and off.
        '''
        p = pexpect.spawn('cat', timeout=10)
        self._expect_echo_on(p)
        self._goodbye_cat(p)

        p = pexpect.spawn('cat', timeout=10, echo=True)
        self._expect_echo_on2(p)
        self._goodbye_cat(p)

        p = pexpect.spawn('cat', timeout=10, echo=False)
        self._expect_echo_off(p)
        self._goodbye_cat(p)

    def test_expect_echo_exact(self):
        '''Like test_expect_echo(), but using expect_exact().
        '''
        p = pexpect.spawn('cat', timeout=10)  # echo=True is default
        p.expect = p.expect_exact
        self._expect_echo_on(p)
        self._goodbye_cat(p)

        p = pexpect.spawn('cat', timeout=10, echo=True)
        p.expect = p.expect_exact
        self._expect_echo_on2(p)
        self._goodbye_cat(p)

        p = pexpect.spawn('cat', timeout=10, echo=False)
        p.expect = p.expect_exact
        self._expect_echo_off(p)
        self._goodbye_cat(p)

    def _expect_echo_on(self, p):
        assert p.echo is True
        p.sendline(b'ONE')
        table = [b'ONE', b'TWO', b'JUNK', pexpect.EOF]
        want_index = table.index(b'ONE')

        # should find 'ONE' twice because echo is on.
        self.assertEqual(p.expect(table), want_index)
        self.assertEqual(p.expect(table), want_index)

    def _expect_echo_on2(self, p):
        assert p.echo is True
        p.sendline(b'TWO')
        table = [pexpect.EOF, b'other-junk', b'JUNK', b'TWO']
        want_index = table.index(b'TWO')

        # should find 'TWO' twice because echo is on.
        self.assertEqual(p.expect(table), want_index)
        self.assertEqual(p.expect(table), want_index)

    def _expect_echo_off(self, p):
        assert p.echo is False
        map(p.sendline, [b'alpha', b'beta'])
        table = [pexpect.EOF, pexpect.TIMEOUT, b'alpha', b'beta', b'gamma']

        # should find each only once because echo is OFF
        want_index = table.index(b'alpha')
        self.assertEqual(p.expect(table), want_index)

        want_index = table.index(b'beta')
        self.assertEqual(p.expect(table), want_index)

    def test_expect_index(self):
        '''This tests that mixed list of regex strings, TIMEOUT, and EOF all
        return the correct index when matched.
        '''
        p = pexpect.spawn('cat', echo=False)
        self._expect_index(p)

    def test_expect_index_exact (self):
        '''Like test_expect_index(), but using expect_exact().
        '''
        p = pexpect.spawn('cat', echo=False)
        p.expect = p.expect_exact
        self._expect_index(p)

    def _expect_index (self, p):
        p.sendline(b'ONE')
        table = [b'junk', b'JUNK', b'ONE', pexpect.EOF]
        want_index = table.index(b'ONE')
        self.assertEqual(p.expect(table), want_index)

        p.sendline(b'TWO')
        table = [pexpect.TIMEOUT, b'TWO', b'three', b'four', pexpect.EOF]
        want_index = table.index(b'TWO')
        self.assertEqual(p.expect(table), want_index)

        p.sendline(b'THREE')
        table = [b'junk', pexpect.TIMEOUT, b'THREE', b'ONE', pexpect.EOF]
        want_index = table.index(b'THREE')
        self.assertEqual(p.expect(table), want_index)

        p.sendline(b'going down ...')
        table = [b'junk', b'JUNK', b'ONE', pexpect.EOF, pexpect.TIMEOUT]
        want_index = table.index(pexpect.TIMEOUT)
        self.assertEqual(p.expect(table, timeout=3), want_index)

        p.sendeof()
        table = [b'junk', b'JUNK', b'ONE', pexpect.TIMEOUT, pexpect.EOF]
        want_index = table.index(pexpect.EOF)
        self.assertEqual(p.expect(table), want_index)

    def test_expect_text_to_subprocess(self):
        the_old_way = subprocess.Popen(args=['ls', '-1Sai', '/bin'],
                                       stdout=subprocess.PIPE
                                       ).communicate()[0].rstrip()
        p = pexpect.spawn('ls -1Sai /bin')
        the_new_way = b''
        while 1:
            i = p.expect ([b'\n', pexpect.EOF])
            the_new_way = the_new_way + p.before
            if i == 1:
                break
        the_new_way = self._strip(the_new_way)
        the_old_way = self._strip(the_old_way)
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)

    def test_expect_exact(self):
        the_old_way = subprocess.Popen(args=['ls', '-1Sai', '/bin'],
                                       stdout=subprocess.PIPE
                                       ).communicate()[0].rstrip()
        p = pexpect.spawn('ls -1Sai /bin')
        the_new_way = b''
        while 1:
            i = p.expect_exact ([b'\n', pexpect.EOF])
            the_new_way = the_new_way + p.before
            if i == 1:
                break
        the_new_way = self._strip(the_new_way)
        the_old_way = self._strip(the_old_way)
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)

        p = pexpect.spawn('echo hello.?world')
        i = p.expect_exact(b'.?')
        self.assertEqual(p.before, b'hello')
        self.assertEqual(p.after, b'.?')

    def test_expect_eof(self):
        the_old_way = subprocess.Popen(args=['/bin/ls', '-1Sai', '/bin'],
                                       stdout=subprocess.PIPE
                                       ).communicate()[0].rstrip()
        p = pexpect.spawn('/bin/ls -1Sai /bin')
        p.expect(pexpect.EOF)
        the_new_way = p.before
        the_new_way = self._strip(the_new_way)
        the_old_way = self._strip(the_old_way)
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)

    @staticmethod
    def _strip(string):
        return (string
                .replace(b'\r\n', b'\n')
                .replace(b'\r', b'\n')
                .replace(b'\n\n', b'\n')
                .rstrip())

    def test_expect_timeout(self):
        p = pexpect.spawn('cat', timeout=5)
        p.expect(pexpect.TIMEOUT) # This tells it to wait for timeout.
        self.assertEqual(p.after, pexpect.TIMEOUT)

    def test_unexpected_eof(self):
        p = pexpect.spawn('ls -Sai /bin')
        try:
            p.expect('_Z_XY_XZ') # Probably never see this in ls output.
        except pexpect.EOF:
            pass
        else:
            self.fail ('Expected an EOF exception.')

    def _before_after(self, p):
        p.timeout = 5

        p.expect(b'5')
        self.assertEqual(p.after, b'5')
        assert p.before.startswith(b'[0, 1, 2'), p.before

        p.expect(b'50')
        self.assertEqual(p.after, b'50')
        assert p.before.startswith(b', 6, 7, 8'), p.before[:20]
        assert p.before.endswith(b'48, 49, '), p.before[-20:]

        p.expect(pexpect.EOF)
        self.assertEqual(p.after, pexpect.EOF)
        assert p.before.startswith(b', 51, 52'), p.before[:20]
        assert p.before.endswith(b', 99]\r\n'), p.before[-20:]

    def test_before_after(self):
        '''This tests expect() for some simple before/after things.
        '''
        p = pexpect.spawn('%s list100.py' % self.PYTHONBIN)
        self._before_after(p)

    def test_before_after_exact(self):
        '''This tests some simple before/after things, for expect_exact(). '''
        p = pexpect.spawn('%s list100.py' % self.PYTHONBIN)
        # mangle the spawn so we test expect_exact() instead
        p.expect = p.expect_exact
        self._before_after(p)

    def _ordering(self, p):
        p.timeout = 5
        p.expect(b'>>> ')

        p.sendline('list(range(4*3))')
        self.assertEqual(p.expect([b'5,', b'5,']), 0)
        p.expect(b'>>> ')

        p.sendline(b'list(range(4*3))')
        self.assertEqual(p.expect([b'7,', b'5,']), 1)
        p.expect(b'>>> ')

        p.sendline(b'list(range(4*3))')
        self.assertEqual(p.expect([b'5,', b'7,']), 0)
        p.expect(b'>>> ')

        p.sendline(b'list(range(4*5))')
        self.assertEqual(p.expect([b'2,', b'12,']), 0)
        p.expect(b'>>> ')

        p.sendline(b'list(range(4*5))')
        self.assertEqual(p.expect([b'12,', b'2,']), 1)

    def test_ordering(self):
        '''This tests expect() for which pattern is returned
        when many may eventually match. I (Grahn) am a bit
        confused about what should happen, but this test passes
        with pexpect 2.1.
        '''
        p = pexpect.spawn(self.PYTHONBIN)
        self._ordering(p)

    def test_ordering_exact(self):
        '''This tests expect_exact() for which pattern is returned
        when many may eventually match. I (Grahn) am a bit
        confused about what should happen, but this test passes
        for the expect() method with pexpect 2.1.
        '''
        p = pexpect.spawn(self.PYTHONBIN)
        # mangle the spawn so we test expect_exact() instead
        p.expect = p.expect_exact
        self._ordering(p)

    def _greed(self, expect):
        # End at the same point: the one with the earliest start should win
        self.assertEqual(expect([b'3, 4', b'2, 3, 4']), 1)

        # Start at the same point: first pattern passed wins
        self.assertEqual(expect([b'5,', b'5, 6']), 0)

        # Same pattern passed twice: first instance wins
        self.assertEqual(expect([b'7, 8', b'7, 8, 9', b'7, 8']), 0)

    def _greed_read1(self, expect):
        # Here, one has an earlier start and a later end. When processing
        # one character at a time, the one that finishes first should win,
        # because we don't know about the other match when it wins.
        # If maxread > 1, this behaviour is currently undefined, although in
        # most cases the one that starts first will win.
        self.assertEqual(expect([b'1, 2, 3', b'2,']), 1)

    def test_greed(self):
        p = pexpect.spawn(self.PYTHONBIN + ' list100.py')
        self._greed(p.expect)

        p = pexpect.spawn(self.PYTHONBIN + ' list100.py', maxread=1)
        self._greed_read1(p.expect)

    def test_greed_exact(self):
        p = pexpect.spawn(self.PYTHONBIN + ' list100.py')
        self._greed(p.expect_exact)

        p = pexpect.spawn(self.PYTHONBIN + ' list100.py', maxread=1)
        self._greed_read1(p.expect_exact)

    def test_bad_arg(self):
        p = pexpect.spawn('cat')
        with assert_raises_msg(TypeError, 'must be one of'):
            p.expect(1)
        with assert_raises_msg(TypeError, 'must be one of'):
            p.expect([1, b'2'])
        with assert_raises_msg(TypeError, 'must be one of'):
            p.expect_exact(1)
        with assert_raises_msg(TypeError, 'must be one of'):
            p.expect_exact([1, b'2'])
        self._goodbye_cat(p)

    def test_timeout_none(self):
        p = pexpect.spawn('echo abcdef', timeout=None)
        p.expect('abc')
        p.expect_exact('def')
        p.expect(pexpect.EOF)
        self.assertFalse(p.isalive())
        self.assertEqual(0, p.exitstatus)

    def test_signal_handling(self):
        '''
            This tests the error handling of a signal interrupt (usually a
            SIGWINCH generated when a window is resized), but in this test, we
            are substituting an ALARM signal as this is much easier for testing
            and is treated the same as a SIGWINCH.

            To ensure that the alarm fires during the expect call, we are
            setting the signal to alarm after 1 second while the spawned process
            sleeps for 2 seconds prior to sending the expected output.
        '''
        def noop(x, y):
            pass
        signal.signal(signal.SIGALRM, noop)

        p1 = pexpect.spawn('%s sleep_for.py 2' % self.PYTHONBIN)
        p1.expect('READY', timeout=10)
        signal.alarm(1)
        p1.expect('END', timeout=10)

if __name__ == '__main__':
    unittest.main()

suite = unittest.makeSuite(ExpectTestCase, 'test')
