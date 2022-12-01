import os
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = [
    'acme >= 1.12.0',
    'cryptography >= 3.3.2',
    'dnspython >= 2.0.0',
    'flask >= 2.0.1',
    'josepy >= 1.2.0',
    'pyOpenSSL >= 20.0.1',
    'requests >= 2.25.1',
    'pyyaml >= 5.3.1',
    'sdnotify >= 0.3.1'
]

extras_require = {
    # Test dependencies
    'tests': [
        'pylint',
        'pytest-cov >= 2.10.1',
        'dnslib >= 0.9.14',
        'requests-mock >= 1.7.0',
    ]
}

# Generate minimum dependencies
extras_require['tests-min'] = [dep.replace('>=', '==') for dep in extras_require['tests']]
if os.getenv('ACMECHIEF_MIN_DEPS', False):
    install_requires = [dep.replace('>=', '==') for dep in install_requires]
    # flash 2.0.1 won't work with werkzeug >= 2.1, bullseye-backports ships 2.0.2
    install_requires.insert(0, 'werkzeug == 2.0.2')

setuptools.setup(
    name="acme-chief",
    version="0.36",
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
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ),
    install_requires=install_requires,
    extras_require=extras_require
)
