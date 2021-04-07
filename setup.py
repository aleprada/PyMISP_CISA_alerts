from setuptools import setup

setup(
    name='PyMISP_CISA_alerts',
    version='0.1.0',
    packages=['cisa', 'config'],
    url='',
    license='MIT',
    author='alejandro.prada',
    author_email='alejandro.prada86@gmail.com',
    description='A tool for gathering via RSS alerts about threats and vulnerabilities related to ICS reported by CISA and send them to a MISP Instance.'
)
