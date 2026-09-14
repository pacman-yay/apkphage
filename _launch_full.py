import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cli

os.chdir(os.path.dirname(os.path.abspath(__file__)))
cli.run_dynamic_analysis()
