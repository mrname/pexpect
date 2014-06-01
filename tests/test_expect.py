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
import sys
import signal
#import pdb

# Many of these test cases blindly assume that sequential directory
# listings of the /bin directory will yield the same results.
# This may not be true, but seems adequate for testing now.
# I should fix this at some point.

# query: For some reason an extra newline occurs under OS X every
# once in a while. Excessive uses of .replace resolve these

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
def hex_dump(src, length=16):
    result=[]
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
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
            raise AssertionError('Expected %s, but no exception was raised' \
                                    % self.errtype)
        if not isinstance(value, self.errtype):
            raise AssertionError('Expected %s, but %s was raised' \
                                    % (self.errtype, etype))

        errstr = str(value)
        if self.msgpart not in errstr:
            raise AssertionError('%r was not in %r' % (self.msgpart, errstr))

        return True


class ExpectTestCase (PexpectTestCase.PexpectTestCase):

    def test_expect_basic (self):
        p = pexpect.spawn('cat')
        p.sendline (b'Hello')
        p.sendline (b'there')
        p.sendline (b'Mr. Python')
        p.expect (b'Hello')
        p.expect (b'there')
        p.expect (b'Mr. Python')
        p.sendeof ()
        p.expect (pexpect.EOF)

    def test_expect_exact_basic (self):
        p = pexpect.spawn('cat')
        p.sendline (b'Hello')
        p.sendline (b'there')
        p.sendline (b'Mr. Python')
        p.expect_exact (b'Hello')
        p.expect_exact (b'there')
        p.expect_exact (b'Mr. Python')
        p.sendeof ()
        p.expect_exact (pexpect.EOF)

    def test_expect_ignore_case(self):
        '''This test that the ignorecase flag will match patterns
        even if case is different using the regex (?i) directive.
        '''
        p = pexpect.spawn('cat')
        p.sendline (b'HELLO')
        p.sendline (b'there')
        p.expect (b'(?i)hello')
        p.expect (b'(?i)THERE')
        p.sendeof ()
        p.expect (pexpect.EOF)

    def test_expect_ignore_case_flag(self):
        '''This test that the ignorecase flag will match patterns
        even if case is different using the ignorecase flag.
        '''
        p = pexpect.spawn('cat')
        p.ignorecase = True
        p.sendline (b'HELLO')
        p.sendline (b'there')
        p.expect (b'hello')
        p.expect (b'THERE')
        p.sendeof ()
        p.expect (pexpect.EOF)

    def test_expect_order (self):
        '''This tests priority-order matching of expect method.'''
        p = pexpect.spawn('cat', echo=False)
        self._expect_order(p)

    def test_expect_order_exact (self):
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
                assert err.args[1].startswith('Invalid argument: getecho() may not be '
                                              'called on this platform')
                raise unittest.SkipTest
            raise
        end_time = time.time() - start
        assert end_time < 10 and end_time > 2, "waitnoecho did not set ECHO off in the expected window of time."

    def test_waitnoecho_default_timeout(self):
        ' This one is mainly here to test default timeout for code coverage. '
        p1 = pexpect.spawn('%s echo_wait.py' % self.PYTHONBIN)
        start = time.time()
        try:
            p1.waitnoecho()
        except OSError as err:
            if err.args[0] == 22:
                assert err.args[1].startswith('Invalid argument: getecho() may not be '
                                              'called on this platform')
                raise unittest.SkipTest
            raise

        end_time = time.time() - start
        assert end_time < 10, "waitnoecho did not set ECHO off in the expected window of time."

    def test_waitnoecho_cat(self):
        ' test that we actually timeout and return False if ECHO is never set off. '
        p1 = pexpect.spawn('cat')
        start = time.time()
        try:
            retval = p1.waitnoecho(timeout=4)
        except OSError as err:
            if err.args[0] == 22:
                assert err.args[1].startswith('Invalid argument: getecho() may not be '
                                              'called on this platform')
                raise unittest.SkipTest
            raise

        end_time = time.time() - start
        assert end_time > 3, "waitnoecho should have waited longer than 2 seconds. retval should be False, retval=%d"%retval
        assert retval==False, "retval should be False, retval=%d"%retval

    def test_expect_echo (self):
        '''This tests that echo can be turned on and off.
        '''
        p = pexpect.spawn('cat', timeout=10)
        self._expect_echo_on(p)

        p = pexpect.spawn('cat', timeout=10, echo=True)
        self._expect_echo_on2(p)

        p = pexpect.spawn('cat', timeout=10, echo=False)
        self._expect_echo_off(p)


    def test_expect_echo_exact (self):
        '''Like test_expect_echo(), but using expect_exact().
        '''
        p = pexpect.spawn('cat', timeout=10)  # echo=True is default
        p.expect = p.expect_exact
        self._expect_echo_on(p)

        p = pexpect.spawn('cat', timeout=10, echo=True)
        p.expect = p.expect_exact
        self._expect_echo_on2(p)

        p = pexpect.spawn('cat', timeout=10, echo=False)
        p.expect = p.expect_exact
        self._expect_echo_off(p)

    def _expect_echo_on(self, p):
        assert p.echo is True
        p.sendline (b'1234') # Should see this twice (once from tty echo and again from cat).
        index = p.expect ([
            b'1234',
            b'abcd',
            b'wxyz',
            pexpect.EOF,
            pexpect.TIMEOUT])
        assert index == 0, (index, str(p))
        index = p.expect ([
            b'1234',
            b'abcd',
            b'wxyz',
            pexpect.EOF])
        assert index == 0, (index, str(p))

    def _expect_echo_on2(self, p):
        assert p.echo is True
        p.sendline (b'7890') # Should see this twice.
        index = p.expect ([pexpect.EOF,b'abcd',b'wxyz',b'7890'])
        assert index == 3, "index="+str(index)
        index = p.expect ([pexpect.EOF,b'abcd',b'wxyz',b'7890'])
        assert index == 3, "index="+str(index)
        p.sendeof()

    def _expect_echo_off(self, p):
        assert p.echo is False
        p.sendline (b'alpha') # Now, should only see this once.
        p.sendline (b'beta') # Should also be only once.
        table = [pexpect.EOF, pexpect.TIMEOUT, b'alpha', b'beta', b'gamma']

        want_index = table.index(b'alpha')
        index = p.expect (table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)


        want_index = table.index(b'beta')
        index = p.expect (table)
        assert index == want_index, ('got', index, table[index],
                                     'wanted', want_index, table[want_index],
                                     'before', p.before,
                                     'after', p.after,
                                     'buffer', p.buffer)

    def test_expect_index (self):
        '''This tests that mixed list of regex strings, TIMEOUT, and EOF all
        return the correct index when matched.
        '''
        #pdb.set_trace()
        p = pexpect.spawn('cat', echo=False)
        self._expect_index(p)

    def test_expect_index_exact (self):
        '''Like test_expect_index(), but using expect_exact().
        '''
        p = pexpect.spawn('cat', echo=False)
        p.expect = p.expect_exact
        self._expect_index(p)

    def _expect_index (self, p):
        p.sendline (b'1234')
        index = p.expect ([b'abcd',b'wxyz',b'1234',pexpect.EOF])
        assert index == 2, "index="+str(index)
        p.sendline (b'abcd')
        index = p.expect ([pexpect.TIMEOUT,b'abcd',b'wxyz',b'1234',pexpect.EOF])
        assert index == 1, "index="+str(index)
        p.sendline (b'wxyz')
        index = p.expect ([b'54321',pexpect.TIMEOUT,b'abcd',b'wxyz',b'1234',pexpect.EOF], timeout=5)
        assert index == 3, "index="+str(index) # Expect 'wxyz'
        p.sendline (b'$*!@?')
        index = p.expect ([b'54321',pexpect.TIMEOUT,b'abcd',b'wxyz',b'1234',pexpect.EOF], timeout=5)
        assert index == 1, "index="+str(index) # Expect TIMEOUT
        p.sendeof ()
        index = p.expect ([b'54321',pexpect.TIMEOUT,b'abcd',b'wxyz',b'1234',pexpect.EOF], timeout=5)
        assert index == 5, "index="+str(index) # Expect EOF

    def test_expect (self):
        the_old_way = subprocess.Popen(args=['ls', '-l', '/bin'],
                stdout=subprocess.PIPE).communicate()[0].rstrip()
        p = pexpect.spawn('ls -l /bin')
        the_new_way = b''
        while 1:
            i = p.expect ([b'\n', pexpect.EOF])
            the_new_way = the_new_way + p.before
            if i == 1:
                break
        the_new_way = the_new_way.rstrip()
        the_new_way = the_new_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        the_old_way = the_old_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)

    def test_expect_exact (self):
        the_old_way = subprocess.Popen(args=['ls', '-l', '/bin'],
                stdout=subprocess.PIPE).communicate()[0].rstrip()
        p = pexpect.spawn('ls -l /bin')
        the_new_way = b''
        while 1:
            i = p.expect_exact ([b'\n', pexpect.EOF])
            the_new_way = the_new_way + p.before
            if i == 1:
                break
        the_new_way = the_new_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        the_old_way = the_old_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)
        p = pexpect.spawn('echo hello.?world')
        i = p.expect_exact(b'.?')
        self.assertEqual(p.before, b'hello')
        self.assertEqual(p.after, b'.?')

    def test_expect_eof (self):
        the_old_way = subprocess.Popen(args=['/bin/ls', '-l', '/bin'],
                stdout=subprocess.PIPE).communicate()[0].rstrip()
        p = pexpect.spawn('/bin/ls -l /bin')
        p.expect(pexpect.EOF) # This basically tells it to read everything. Same as pexpect.run() function.
        the_new_way = p.before
        the_new_way = the_new_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        the_old_way = the_old_way.replace(b'\r\n', b'\n'
                ).replace(b'\r', b'\n').replace(b'\n\n', b'\n').rstrip()
        assert the_old_way == the_new_way, hex_diff(the_old_way, the_new_way)

    def test_expect_timeout (self):
        p = pexpect.spawn('cat', timeout=5)
        p.expect(pexpect.TIMEOUT) # This tells it to wait for timeout.
        self.assertEqual(p.after, pexpect.TIMEOUT)

    def test_unexpected_eof (self):
        p = pexpect.spawn('ls -l /bin')
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
        '''This tests some simple before/after things, for
        expect_exact(). (Grahn broke it at one point.)
        '''
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

    def test_timeout_none(self):
        p = pexpect.spawn('echo abcdef', timeout=None)
        p.expect('abc')
        p.expect_exact('def')
        p.expect(pexpect.EOF)

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

suite = unittest.makeSuite(ExpectTestCase,'test')

#fout = open('delete_me_1','wb')
#fout.write(the_old_way)
#fout.close
#fout = open('delete_me_2', 'wb')
#fout.write(the_new_way)
#fout.close

