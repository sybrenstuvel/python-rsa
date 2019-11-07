import pathlib
import unittest

from flake8.api import legacy as flake8

test_modules = ['rsa', 'tests']


class Flake8RunnerTest(unittest.TestCase):
    def test_run_flake8(self):
        proj_root = pathlib.Path(__file__).parent.parent
        paths = [proj_root / dirname for dirname in test_modules]

        style_guide = flake8.get_style_guide()
        report = style_guide.check_files(paths)

        errors = report.get_statistics('')
        if errors:
            self.fail('\n'.join(['Flake8 errors:'] + errors))
