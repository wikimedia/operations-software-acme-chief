import os
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = [
    'acme >= 0.28.0',
    'cryptography >= 2.3',
    'dnspython >= 1.16.0',
    'flask >= 1.0.2',
    'josepy >= 1.1.0',
    'pyOpenSSL >= 19.0.0',
    'requests >= 2.20.0',
    'pyyaml >= 3.13'
]

extras_require = {
    # Test dependencies
    'tests': [
        'pylint',
        'pytest-cov >= 1.8.0',
        'dnslib >= 0.9.7',
        'requests-mock >= 1.0.0',
    ]
}

# Generate minimum dependencies
extras_require['tests-min'] = [dep.replace('>=', '==') for dep in extras_require['tests']]
if os.getenv('ACMECHIEF_MIN_DEPS', False):
    install_requires = [dep.replace('>=', '==') for dep in install_requires]

setuptools.setup(
    name="acme-chief",
    version="0.17",
    author="Alex Monk",
    author_email="krenair@gmail.com",
    description="Python application to request certificates from ACME servers and distribute to authorised clients.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://phabricator.wikimedia.org/diffusion/OSCC/",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'acme-chief-backend = acme_chief.acme_chief:main'
        ]
    },
    classifiers=(
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ),
    install_requires=install_requires,
    extras_require=extras_require
)
