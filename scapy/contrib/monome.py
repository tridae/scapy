# This file is part of Scapy.
# See http://www.secdev.org/projects/scapy for more information.
#
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (C) 2020 tridae

# scapy.contrib.description = monome serial protocol
# scapy.contrib.status = loads

"""
monome serial device protocol layer for Scapy
"""

import struct

from scapy.fields import BitEnumField, BitField, BitFieldLenField, \
    ByteEnumField, ShortField, StrField, StrLenField
from scapy.packet import Packet, bind_layers
from scapy.error import warning
from scapy.compat import raw

class Monome(Packet):
    """A class to model packets of the monome serial protocol"""
    name = "monome"

    fields_desc = [BitEnumField("section", 0, 4, {
			0: "system",
			1: "led grid",
			2: "key grid",
			3: "digital out",
			4: "digital line in",
			5: "encoder",
			6: "analog in",
			7: "analog out",
			8: "tilt",
			9: "variable 64led ring"}),
                   BitField("command", 0, 4),
                   ]

    def getfieldval(self, attr):
        v = getattr(self, attr)
        if v:
            return v
        return Packet.getfieldval(self, attr)

    def post_dissect(self, pay):
        for k in self.options:
            if k[0] == "Content-Format":
                self.content_format = k[1]
        return pay
