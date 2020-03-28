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
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Interface monitoring")
args = parser.parse_args()

key= b'\xaa\xaa\xaa\xaa\xaa'

nbFrag = 3

# Chiffrement + ajout de l'ICV
def encryptData(data, seed):
    # CRC
    icv = zlib.crc32(data).to_bytes(4, 'little')
    alldata = data + icv

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(alldata)

    # nouvelle donnée et ICV dans la trame modèle
    wepdata = ciphertext[:-4]
    icv = unpack('!L', ciphertext[-4:])[0]
    return wepdata, icv


#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
model = rdpcap('arp.cap')[0]
models = []
for i in range(nbFrag):
    models.append(model.copy())

# rc4 seed est composé de IV+clé
seed = model.iv+key

# cleartext (marche uniquement avec la même longueur si on ne change pas les flags)
cleartext = []

# Génération de valeur entre A et C pour chaque fragment.
for i in range(nbFrag):
    cleartext.append((chr(ord("A") + i) * 36).encode('ascii'))

for i in range(len(cleartext)):
    wepdata, icv = encryptData(cleartext[i], seed)
    models[i].wepdata = wepdata
    models[i].icv = icv
    models[i].SC = i
    if i < len(cleartext) - 1:
        models[i].FCfield.value += 4 # 4 pour le flag MF




# enregistre la trame dans un fichier cap
wrpcap("wep_frag.cap",models)

sendp(models, iface=args.interface, loop=1, inter=0.2)

