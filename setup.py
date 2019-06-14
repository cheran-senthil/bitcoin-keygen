# Copyright (C) 2019 Cheran Senthilkumar
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from os import path

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="bitcoin-keygen",
    version="v0.1.1",
    description="Bitcoin Utility Functions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cheran-senthil/bitcoin-keygen",
    author="Cheran",
    aurthor_email="cheran.v.senthil@gmail.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="bitcoin keygen python script blockchain cryptography cryptocurrency",
    packages=find_packages(),
    project_urls={
        "Bug Reports": "https://github.com/cheran-senthil/bitcoin-keygen/issues",
        "Source": "https://github.com/cheran-senthil/bitcoin-keygen/",
    },
)
