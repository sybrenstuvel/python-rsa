import unittest
import sys


if sys.hexversion < 0x2070000:
    # Monkey-patch unittest.TestCase to add assertIsInstance on Python 2.6

    def assertIsInstance(self, obj, cls, msg=None):
        """Same as self.assertTrue(isinstance(obj, cls)), with a nicer default message."""
        if not isinstance(obj, cls):
            self.fail('%r is not an instance of %r but is a %r' % (obj, cls, type(obj)))

    unittest.TestCase.assertIsInstance = assertIsInstance
