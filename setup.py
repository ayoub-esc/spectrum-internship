from setuptools import setup

setup(
    name='CPETenable',
    version='1',
    packages=['CPETenable'],
    install_requires=['pycurl', 'http_curl_wrapper', 'ElementsAPI'],
    license='NA',
    author='Ayoub Benchaita',
    author_email='Ayoub.benchaita@Charter.com',
    description='Pytenable module for automatically running Tenable vulnderability scans on CPE devices'
)
