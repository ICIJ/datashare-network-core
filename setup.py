import sys
from dsnet import __version__

from setuptools import setup, find_packages

py_version = sys.version_info[:2]
if py_version < (3, 6):
    raise Exception("datashare-network requires Python >= 3.6.")

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='datashare-network-core',
      version=__version__,
      packages=find_packages(),
      description="Core Datashare Network Library",
      use_pipfile=True,
      long_description=long_description,
      long_description_content_type="text/markdown",
      url="https://github.com/icij/datashare-network-lib",
      test_suite='nose.collector',
      tests_require=['nose', 'responses'],
      setup_requires=['setuptools-pipfile'],
      keywords=['datashare', 'api', 'network', 'cryptography'],
      classifiers=[
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: GNU Affero General Public License v3",
          "Operating System :: OS Independent",
          "Topic :: Security :: Cryptography"
      ],
      python_requires='>=3.6',
      )
