# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path

# The directory containing this file
HERE = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()



# This call to setup() does all the work
setup(
    name="maxmods",
    version="0.1.4",
    description="A library of all the usefull code snipits I make and maintain",
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
    packages=['maxmods'],
    include_package_data=True,
    install_requires=['requests',
        'jsonpath_ng',
        'flask_sqlalchemy',
        'flask',
        'flask_restful',
        'cryptography',
        'keyboard',
        'pygame',
        'numpy']
)
