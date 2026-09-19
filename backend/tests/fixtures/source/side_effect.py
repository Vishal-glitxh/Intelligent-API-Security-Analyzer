# This file has top-level execution side-effects.
# If imported or executed, it sets an environment variable.
# The static analyzer must NEVER execute this code.
import os

os.environ["STATIC_ANALYZER_TEST_EXECUTED"] = "PWNED"
