from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="simple-network-scanner",
    version="1.0.4",
    author="Dylan Gallemard",
    author_email="dylangallemard@gmail.com",
    description="A comprehensive network port scanner with vulnerability detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Zeusfail/Simple-Network-Scanner",
    packages=find_packages(),
    py_modules=["main"],  
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "scapy>=2.4.0",
        "rich>=12.0.0", 
    ],
    entry_points={
        "console_scripts": [
            "netscanner=main:main", 
        ],
    },
)