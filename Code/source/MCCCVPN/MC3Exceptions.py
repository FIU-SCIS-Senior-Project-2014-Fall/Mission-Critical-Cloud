from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid

class ValidationError(Exception):
    def __init__(self, message, errors):

        # Call the base class constructor with the parameters it needs
        super(ValidationError, self).__init__(message)

        # Now for your custom code...
        self.errors = errors