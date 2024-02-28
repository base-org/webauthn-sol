# WebAuthn Assertions Generator

The `assertions_generator.py` script is a utility script that dynamically generates WebAuthn assertions and store them in a json file (used for fuzz tests).

When executing `assertions_generator.py` a [Flask](https://flask.palletsprojects.com/en/3.0.x/) app (see `app.py`) is launched and interacted with through a headless **Chrome** browser using [Selenium](https://selenium-python.readthedocs.io/) to generate valid WebAuthn assertions.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the requirements:

```bash
pip install -r ./requirements.txt
```

## Usage

```bash
$ python3 ./assertions_generator.py --help

usage: assertions_generator.py [-h] count

positional arguments:
  count       Number of assertions to generate

optional arguments:
  -h, --help  show this help message and exit
```