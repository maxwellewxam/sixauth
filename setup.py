# Always prefer setuptools over distutils
from setuptools import setup, find_packages
import subprocess
# To use a consistent encoding
from codecs import open
from os import path

# The directory containing this file
HERE = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

mm_remote_version = (
    subprocess.run(["git", "describe", "--tags"], stdout=subprocess.PIPE)
    .stdout.decode("utf-8")
    .strip()
)

if "-" in mm_remote_version:
    # when not on tag, git describe outputs: "1.3.3-22-gdf81228"
    # pip has gotten strict with version numbers
    # so change it to: "1.3.3+22.git.gdf81228"
    # See: https://peps.python.org/pep-0440/#local-version-segments
    v,i,s = mm_remote_version.split("-")
    mm_remote_version = v + "+" + i + ".git." + s

assert "-" not in mm_remote_version
assert "." in mm_remote_version

# This call to setup() does all the work
setup(
    name="maxmods",
    version=mm_remote_version,
    description="A library of all the useful code snippets I make and maintain",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/maxwellewxam/maxmods/",
    author="Max Colby",
    author_email="maxwellipe43662@gmail.com",
    license="MIT",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent"
    ],
    packages=find_packages(),#['maxmods', 'maxmods.auth', 'maxmods.menu', 'maxmods.auth.auth_backend'],
    include_package_data=True,
    install_requires=['requests',
        'jsonpath-ng',
        'flask_sqlalchemy',
        'flask',
        'flask_restful',
        'cryptography',
        'keyboard',
        'pygame',
        'numpy',
        'bcrypt']
)
