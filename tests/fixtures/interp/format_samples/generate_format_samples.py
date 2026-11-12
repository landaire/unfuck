# Records CPython's outcomes for the samples in format_samples.py, for
# tests/interp_format_samples.rs. Run it with the Windows 2.7.12 build:
#
#   /var/mnt/build/winpy/winpy2712.sh generate_format_samples.py

import os

import format_samples

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, 'format_samples.expected'), 'wb') as output:
    output.write(format_samples.OUTCOMES + '\n')
