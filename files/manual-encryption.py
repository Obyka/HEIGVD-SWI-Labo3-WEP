#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Florian Polier & Eric Tran"

from scapy.all import *
import binascii
# Zlib is here to provide CRC32 functions
import zlib
from rc4 import RC4
from struct import *

key= b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
model = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = model.iv+key

# cleartext (marche uniquement avec la même longueur si on ne change pas les flags)
cleartext = ("A"*36).encode('ascii')

# CRC
icv = zlib.crc32(cleartext).to_bytes(4, 'little')
alldata = cleartext + icv

# chiffrement rc4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(alldata)

# nouvelle donnée et ICV dans la trame modèle
model.wepdata = ciphertext[:-4]
model.icv = unpack('!L', ciphertext[-4:])[0]

# enregistre la trame dans un fichier cap
wrpcap("wep.cap",model)

