from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

with open('VERSION') as f:
    version = f.read()

setup(
    name='fafnir',  # Replace with your project name
    version = version,
    author = 'syn-4ck',
    author_email = 'repoJFM@protonmail.com',
    url = 'https://github.com/syn-4ck/fafnir',
    description = 'Software supply chain security tool to automate appsec vulnerability detection',
    long_description = 'Fafnir is an open-source tool that allows for the complete automation ' +
        'of launching different security tools detecting vulnerabilities in the application''s, code',
    license = "MIT license",
    packages = find_packages(exclude=["tests",".github",".github"]),
    install_requires = requirements,
    entry_points={
        'console_scripts': [
            'fafnir = src.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License 2.0",
        "Operating System :: OS Independent",
    ]
)