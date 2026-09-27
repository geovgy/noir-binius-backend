"""Regression tests for overlapping Foundry gas labels."""
from pathlib import Path
import itertools
import runpy
import unittest

gas_measurement = runpy.run_path(str(Path(__file__).with_name('solidity-deployment-e2e.py')))['gas_measurement']


class GasLogTests(unittest.TestCase):
    def test_every_output_order_retains_distinct_measurements(self):
        values = {
            'hinted verification gas': 174751017,
            'program input hinted verification gas': 165902262,
            'verification gas (cold program storage)': 199000182,
            'program input native verification gas': 190103933,
            'creation gas excluding bytecode file read': 518124690,
        }
        for order in itertools.permutations(values):
            log = '\n'.join(f'  {label}: {values[label]}' for label in order)
            for label, value in values.items():
                self.assertEqual(gas_measurement(log, label), value)

    def test_missing_duplicate_or_partial_labels_fail(self):
        label = 'hinted verification gas'
        for log in ['', '  program input hinted verification gas: 1',
                    'hinted verification gas: 1\nhinted verification gas: 2',
                    'hinted verification gas: 1 trailing text',
                    'hinted verification gas: -1']:
            with self.assertRaises(AssertionError):
                gas_measurement(log, label)
        self.assertEqual(gas_measurement('\thinted verification gas: 0  \n', label), 0)


if __name__ == '__main__':
    unittest.main()
