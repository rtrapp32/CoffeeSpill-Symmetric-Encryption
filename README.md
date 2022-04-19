# CoffeeSpill-Symmetric-Encryption
A simple symmetric encryption algorithm designed to teach aspects of cryptography and cryptanalysis.
This encryption algorithim based on a symetric Feistel Cipher and operates using four rounds.
Feistel ciphers are used by encryption algorithms like DES, and TwoFish.

This encryption algorithm is a block cipher which uses a 512 bit key and 256 bit blocks.

This cipher was created as an educational tool.
Making this encryption algorithm helped me understand how digital cryptography works at a lower level.

As this algorithm is currently implemented, only strings which can be expressed using UTF-8 can be encrypted using this script. 

DO NOT USE FOR PRACTICAL APPLICATIONS, THIS ENCRYPTION METHOD IS INSECURE!! Use a trusted algorithm instead like AES-256 - GCM. This en
