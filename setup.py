from setuptools import setup
from os import path
from ironworker import __version__

with open(path.join(path.dirname(__file__), 'requirements.txt')) as f:
    reqs = [l for l in f.read().strip().split('\n') if not l.startswith('-')]

setup(
    name='ironworker',
    version=__version__.__version__,
    description='Python Interface to Iron.io Worker API',
    long_description=open('README.md').read(),
    license=open('LICENSE').read(),
    author='Adam Jaso',
    author_email='ajaso@hsdp.io',
    packages=['ironworker'],
    package_dir={'ironworker': 'ironworker'},
    install_requires=reqs,
    url='https://github.com/hsdp/python-ironworker',
)
