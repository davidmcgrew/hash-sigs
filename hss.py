#!/usr/bin/python

"""
   Copyright (c) 2016 Cisco Systems, Inc.
   All rights reserved.
   
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   
     Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
   
     Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.
   
     Neither the name of the Cisco Systems, Inc. nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.
   
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
   COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
   OF THE POSSIBILITY OF SUCH DAMAGE.

   hss.py

   Reference implementation for Leighton-Micali Hash Based Signatures
   (HBS) and Hierarchical Signature System (HSS), as per the Internet
   Draft draft-mcgrew-hash-sigs-05.txt.
"""

import sys
import binascii
import struct    
import os.path
from Crypto.Hash import SHA256
from Crypto import Random

# error codes
#
err_private_key_exhausted = 'error: attempted overuse of private key'
err_unknown_typecode      = 'error: unrecognized typecode'
err_bad_length            = 'error: parameter has wrong length'
err_bad_value             = 'error: parameter has inadmissable value'

err_list = [ 
    err_private_key_exhausted,
    err_unknown_typecode,
    err_bad_length,
    err_bad_value
]

def err_handle(err):
    if err.args[0] in err_list:
        print str(err.args)
    else:
        raise

# return codes
#
INVALID = 0
VALID   = 1

# Diversification constants
#
D_ITER = chr(0x00) # in the iterations of the LM-OTS algorithms
D_PBLC = chr(0x01) # when computing the hash of all of the iterates in the LM-OTS algorithm 
D_MESG = chr(0x02) # when computing the hash of the message in the LMOTS algorithms
D_LEAF = chr(0x03) # when computing the hash of the leaf of an LMS tree
D_INTR = chr(0x04) # when computing the hash of an interior node of an LMS tree
D_PRG  = chr(0x05) # when computing LMS private keys pseudorandomly

# LMOTS typecodes and parameters
#
lmots_sha256_n32_w1 = 0x00000001
lmots_sha256_n32_w2 = 0x00000002
lmots_sha256_n32_w4 = 0x00000003
lmots_sha256_n32_w8 = 0x00000004

lmots_params = {
    #                     n   p    w  ls  
    lmots_sha256_n32_w1: (32, 265, 1, 7), 
    lmots_sha256_n32_w2: (32, 133, 2, 6), 
    lmots_sha256_n32_w4: (32, 67,  4, 4), 
    lmots_sha256_n32_w8: (32, 34,  8, 0)
}

lmots_name = {
    lmots_sha256_n32_w1: "LMOTS_SHA256_N32_W1", 
    lmots_sha256_n32_w2: "LMOTS_SHA256_N32_W2", 
    lmots_sha256_n32_w4: "LMOTS_SHA256_N32_W4", 
    lmots_sha256_n32_w8: "LMOTS_SHA256_N32_W8" 
}

# LMS typecodes and parameters
#
lms_sha256_m32_h5  = 0x00000001
lms_sha256_m32_h10 = 0x00000002
lms_sha256_m32_h15 = 0x00000003
lms_sha256_m32_h20 = 0x00000004

lms_params = {
    #                    m,  h,  LenI
    lms_sha256_m32_h5:  (32, 5,  64), 
    lms_sha256_m32_h10: (32, 10, 64), 
    lms_sha256_m32_h15: (32, 15, 64), 
    lms_sha256_m32_h20: (32, 20, 64)
}

lms_name = {
    lms_sha256_m32_h5:  "LMS_SHA256_M32_H5", 
    lms_sha256_m32_h10: "LMS_SHA256_M32_H10", 
    lms_sha256_m32_h15: "LMS_SHA256_M32_H15", 
    lms_sha256_m32_h20: "LMS_SHA256_M32_H20"
}

# ***************************************************************
#                                                               |
#                           Utilities                           |
#                                                               |
# ***************************************************************

def H(x):
    """
    SHA256 hash function
    :param x: input that will be hashed
    :return: list of 32 bytes, hash digest
    """
    h = SHA256.new()
    h.update(x)
    return h.digest()

def u32str(x):
    """
    Integer to 4-byte string conversion
    :param x: integer that will be converted
    :return: 4-byte string representing integer
    """
    return struct.pack('>I', x)

def u16str(x):
    """
    Integer to 2-byte string conversion
    :param x: integer that will be converted
    :return: 2-byte string representing integer
    """
    return struct.pack('>H', x)

def u8str(x):
    """
    Integer to 1-byte string conversion
    :param x: integer that will be converted
    :return: 1-byte representing integer
    """
    return chr(x)

def deserialize_u32(buffer):
    if (len(buffer) != 4):
        raise ValueError(err_bad_length, str(len(buffer)))
    return int(buffer.encode('hex'), 16) 

def typecode_peek(buffer):
    if (len(buffer) != 4):
        raise ValueError(err_bad_length, str(len(buffer)))
    return int(buffer.encode('hex'), 16) 

def serialize_array(array):
    result = ""
    for e in array:
        result = result + e
    return result

def string_to_hex(x):
    return binascii.hexlify(bytearray(x))

class PrintUtl(object):
    margin = 12
    width = 16

    @classmethod
    def print_hex(cls, LHS, RHS, comment=""):
        s = RHS
        LHS = LHS + (" " * (cls.margin - len(LHS)))
        if len(s) < cls.width and comment != "":
            comment = " " * 2 * (cls.width - len(s)) + " # " + comment
        print LHS + string_to_hex(s[0:cls.width]) + comment
        s = s[cls.width:]
        LHS = " " * cls.margin
        while len(s) is not 0:
            print LHS + string_to_hex(s[0:cls.width])
            s = s[cls.width:]

    @classmethod
    def print_line(cls):
        print "-" * (cls.margin + 2*cls.width)


# ***************************************************************
#                                                               |
#                   LM-OTS functionality                        |
#                                                               |
# ***************************************************************

entropySource = Random.new()

class LmotsSignature():
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, C, y, typecode=lmots_sha256_n32_w8):
        self.C = C
        self.y = y
        self.type = typecode

    def serialize(self):
        return u32str(self.type) + self.C + serialize_array(self.y)

    @classmethod
    def deserialize(cls, buffer):
        lmots_type = typecode_peek(buffer[0:4])
        if lmots_type in lmots_params:
            n, p, w, ls = lmots_params[lmots_type]
        else:
            raise ValueError(err_unknown_typecode, str(lmots_type))
        if (len(buffer) != cls.bytes(lmots_type)):
            raise ValueError(err_bad_length)
        C = buffer[4:n+4]
        y = list()
        pos = n+4
        for i in xrange(0, p):
            y.append(buffer[pos:pos+n])
            pos = pos + n
        return cls(C, y, lmots_type)
 
    @classmethod
    def bytes(cls, lmots_type):
        n, p, w, ls = lmots_params[lmots_type]
        return 4 + n*(p+1)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS signature"
        PrintUtl.print_hex("LMOTS type", u32str(self.type), lmots_name[self.type])
        PrintUtl.print_hex("C", self.C)
        for i, e in enumerate(self.y):
            PrintUtl.print_hex("y[" + str(i) + "]", e)
        PrintUtl.print_line()


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    # Algorithm 0: Generating an LMOTS Private Key
    #
    def __init__(self, S=None, xq=None, lmots_type=lmots_sha256_n32_w8):   
        n, p, w, ls = lmots_params[lmots_type]
        if S is None:
            self.S = entropySource.read(n)
        else:
            self.S = S
        self.x = list()
        if xq is None:
            for i in xrange(0, p):
                self.x.append(entropySource.read(n))
        else:
            for i in xrange(0, p):
                self.x.append(xq)
                xq = H(self.S + xq + u16str(i+1) + D_PRG)
        self.type = lmots_type
        self._signatures_remaining = 1

    def num_signatures_remaining(self):
        return self._signatures_remaining

    # Algorithm 1: Generating a Public Key From a Private Key
    #
    def get_public_key(self): 
        n, p, w, ls = lmots_params[self.type]
        hash = SHA256.new()
        hash.update(self.S)
        for i, x in enumerate(self.x):
            tmp = x
            for j in xrange(0, 2**w - 1):
                tmp = H(self.S + tmp + u16str(i) + u8str(j) + D_ITER)
            hash.update(tmp)
        hash.update(D_PBLC)
        return LmotsPublicKey(self.S, hash.digest(), self.type)

    # Algorithm 3: Generating a Signature From a Private Key and a Message
    #
    def sign(self, message):
        if self._signatures_remaining != 1:
            raise ValueError(err_private_key_exhausted)
        n, p, w, ls = lmots_params[self.type]
        C = entropySource.read(n) 
        hashQ = H(self.S + C + message + D_MESG)
        V = hashQ + checksum(hashQ, w, ls)
        y = list()
        for i, x in enumerate(self.x):
            tmp = x
            for j in xrange(0, coef(V, i, w)):
                tmp = H(self.S + tmp + u16str(i) + u8str(j) + D_ITER)
            y.append(tmp)
        self._signatures_remaining = 0
        return LmotsSignature(C, y, self.type).serialize()

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS private key"
        PrintUtl.print_hex("LMS type", u32str(self.type), lms_name[self.type])
        PrintUtl.print_hex("S", self.S)
        for i, x in enumerate(self.x):
            PrintUtl.print_hex("x[" + str(i) + "]", x)
        PrintUtl.print_line()

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for t in lmots_params.keys():
            param_list.append({'lmots_type':t})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return LmotsPublicKey

class LmotsPublicKey:
    """
    Leighton-Micali One Time Signature Public Key
    """
    def __init__(self, S, K, lmots_type):
        self.S = S
        self.K = K
        self.type = lmots_type

    # Algorithm 4: Verifying a Signature and Message Using a Public Key
    #
    def verify(self, message, sig):
        if self.K == lmots_sig_to_pub(sig, self.S, self.type, message):
            return VALID
        else:
            return INVALID

    def serialize(self):
        return u32str(self.type) + self.S + self.K 

    @classmethod
    def deserialize(cls, buffer):
        lmots_type = typecode_peek(buffer[0:4])
        if lmots_type in lmots_params:
            n, p, w, ls = lmots_params[lmots_type]
        else:
            raise ValueError(err_unknown_typecode)
        if len(buffer) != 4+2*n:
            raise ValueError(err_bad_length)
        S = buffer[4:4+n]
        K = buffer[4+n:4+2*n]
        return cls(S, K, lmots_type)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS public key"
        PrintUtl.print_hex("LMOTS type", u32str(self.type), lmots_name[self.type])
        PrintUtl.print_hex("S", self.S)
        PrintUtl.print_hex("K", self.K)
        PrintUtl.print_line()

# Algorithm 2: Merkle Checksum Calculation
#
def coef(S, i, w):
    return (2**w - 1) & (ord(S[i*w/8]) >> (8 - (w*(i%(8/w)) + w)))

def checksum(x, w, ls):
    sum = 0
    num_coefs = len(x)*(8/w)
    for i in xrange(0, num_coefs):
        sum = sum + (2**w - 1) - coef(x, i, w)
    return u16str(sum << ls)

def lmots_sig_to_pub(sig, S, lmots_type, message):
    signature = LmotsSignature.deserialize(sig)
    if (signature.type != lmots_type):
        raise ValueError(err_unknown_typecode)
    n, p, w, ls = lmots_params[lmots_type]
    hashQ = H(S + signature.C + message + D_MESG)
    V = hashQ + checksum(hashQ, w, ls)
    hash = SHA256.new()
    hash.update(S)
    for i, y in enumerate(signature.y):
        tmp = y
        for j in xrange(coef(V, i, w), 2**w - 1):
            tmp = H(S + tmp + u16str(i) + u8str(j) + D_ITER)
        hash.update(tmp)
    hash.update(D_PBLC)
    return hash.digest()
 
# ***************************************************************
#                                                               |
#               LMS N-time signatures functions                 |
#                                                               |
#           h = 10 # height (number of levels -1) of tree       |
# ***************************************************************

def serialize_lms_sig(typecode, q, lmots_sig, path):
    return u32str(typecode) + u32str(q) + lmots_sig + serialize_array(path)

def deserialize_lms_sig(buffer):
    lms_type = typecode_peek(buffer[0:4])
    if lms_type in lms_params:
        m, h, LenI = lms_params[lms_type]
    else:
        raise ValueError(err_unknown_typecode, str(lms_type))
    q = deserialize_u32(buffer[4:8])
    if (q >= 2**h):
        raise ValueError(err_bad_value)
    lmots_type = typecode_peek(buffer[8:12])
    if lmots_type in lmots_params:
        pos = 8 + LmotsSignature.bytes(lmots_type)
    else:
        raise ValueError(err_unknown_typecode, str(lmots_type))
    lmots_sig = buffer[8:pos]
    path = list()
    for i in xrange(0, h):
        path.append(buffer[pos:pos+m])
        pos = pos + m
    return lms_type, q, lmots_sig, path

def parse_lms_sig(buffer):
    lms_type = typecode_peek(buffer[0:4])
    if lms_type in lms_params:
        m, h, LenI = lms_params[lms_type]
    else:
        raise ValueError(err_unknown_typecode)
    lmots_type = typecode_peek(buffer[8:12])
    if lmots_type in lmots_params:
        pos = 8 + LmotsSignature.bytes(lmots_type)
    else:
        raise ValueError(err_unknown_typecode)
    pos = pos + h*m
    return buffer[0:pos], buffer[pos:]

def print_lms_sig(sig):
    PrintUtl.print_line()
    print "LMS signature"
    lms_type, q, lmots_sig, path = deserialize_lms_sig(sig)
    PrintUtl.print_hex("LMS type", u32str(lms_type), lms_name[lms_type])
    PrintUtl.print_hex("q", u32str(q))
    LmotsSignature.deserialize(lmots_sig).print_hex()
    for i, e in enumerate(path):
        PrintUtl.print_hex("path[" + str(i) + "]", e)

class LmsPrivateKey(object):
    """
    Leighton-Micali Signature Private Key
    """
    def __init__(self, lms_type=lms_sha256_m32_h10, lmots_type=lmots_sha256_n32_w8,
                 SEED=None, I=None, qinit=0, nodes=None, pub=None):
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.priv = list()
        self.pub = list()
        if I is None:
            self.I = entropySource.read(LenI)
        else:
            if (len(I) != LenI):
                raise ValueError(err_bad_length, str(len(I)))
            self.I = I
        if SEED is None:
            SEED = entropySource.read(n)
        else:
            if (len(SEED) != n):
                raise ValueError(err_bad_length, str(len(SEED)))
        self.SEED = SEED 

        if nodes is None:
            for q in xrange(0, 2**h):
                S = self.I + u32str(q)
                xq0 = H(S + SEED + u16str(0) + D_PRG)
                ots_priv = LmotsPrivateKey(S=S, xq=xq0, lmots_type=lmots_type)
                ots_pub = ots_priv.get_public_key()
                self.priv.append(ots_priv)
                self.pub.append(ots_pub)
        else:
            self.nodes = nodes
            self.pub = pub
        self.leaf_num = qinit
        self.nodes = {}
        self.lms_pub_value = self.T(1)

    def get_path(self, node_num):
        path = list()
        while node_num > 1:
            if (node_num % 2):
                path.append(self.nodes[node_num - 1])
            else:
                path.append(self.nodes[node_num + 1])
            node_num = node_num/2
        return path
    
    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]
        
    def sign(self, message):
        m, h, LenI = lms_params[self.lms_type]
        if (self.leaf_num >= 2**h):
            raise ValueError(err_private_key_exhausted)
        ots_sig = self.get_next_ots_priv_key().sign(message)
        path = self.get_path(self.leaf_num + 2**h)
        leaf_num = self.leaf_num
        self.leaf_num = self.leaf_num + 1
        return serialize_lms_sig(self.lms_type, leaf_num, ots_sig, path)

    # Algorithm for computing root and other nodes (alternative to Algorithm 6)
    #
    def T(self, r):
        m, h, LenI = lms_params[self.lms_type]
        if (r >= 2**h):
            self.nodes[r] = H(self.I + self.pub[r - 2**h].K + u32str(r) + D_LEAF)
            return self.nodes[r]
        else:
            self.nodes[r] = H(self.I + self.T(2*r) + self.T(2*r+1) + u32str(r) + D_INTR)
            return self.nodes[r] 

    def num_signatures_remaining(self):
        m, h, LenI = lms_params[self.lms_type]
        return 2**h - self.leaf_num

    def is_exhausted(self):
        return (0 == self.num_signatures_remaining())

    def max_signatures(self):
        m, h, LenI = lms_params[self.lms_type]
        return 2**h

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS private key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type), lms_name[self.lms_type])
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type), lmots_name[self.lmots_type])
        PrintUtl.print_hex("I", self.I)
        PrintUtl.print_hex("SEED", self.SEED)
        PrintUtl.print_hex("q", u32str(self.leaf_num))
        PrintUtl.print_hex("pub", self.lms_pub_value)

    def get_public_key(self):
        return LmsPublicKey(self.I, self.lms_pub_value, self.lms_type, self.lmots_type)

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for x in lmots_params.keys():
            for y in lms_params.keys():
                param_list.append({'lmots_type':x, 'lms_type':y})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return LmsPublicKey

    def serialize(self):
        return u32str(self.lms_type) + u32str(self.lmots_type) + self.SEED + self.I + u32str(self.leaf_num) 

    @classmethod
    def deserialize(cls, buffer):
        lms_type = deserialize_u32(buffer[0:4])
        lmots_type = deserialize_u32(buffer[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        SEED = buffer[8:8+n]
        I = buffer[8+n:8+n+LenI]
        q = deserialize_u32(buffer[8+n+LenI:8+n+LenI+4])
        return cls(lms_type, lmots_type, SEED, I, q)

    @classmethod
    def deserialize_print_hex(cls, buffer):
        PrintUtl.print_line()
        print "LMS private key"
        lms_type = deserialize_u32(buffer[0:4])
        lmots_type = deserialize_u32(buffer[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        SEED = buffer[8:8+n]
        I = buffer[8+n:8+n+LenI]
        q = deserialize_u32(buffer[8+n+LenI:8+n+LenI+4])
        PrintUtl.print_hex("lms_type", u32str(lms_type))
        PrintUtl.print_hex("lmots_type", u32str(lmots_type))
        PrintUtl.print_hex("SEED", SEED)
        PrintUtl.print_hex("I", I)
        PrintUtl.print_hex("leaf_num", u32str(q))
        PrintUtl.print_line()

    @classmethod
    def parse(cls, buffer):
        lms_type = deserialize_u32(buffer[0:4])
        lmots_type = deserialize_u32(buffer[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        return buffer[:8+n+LenI], buffer[8+n+LenI:]        


class LmsPrivateKeyNonvolatile(LmsPrivateKey):
    
    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]
        

class LmsPublicKey(object):
    """
    Leighton-Micali Signature Public Key
    """
    def __init__(self, I, value, lms_type, lmots_type):
        self.I = I
        self.value = value
        self.lms_type = lms_type
        self.lmots_type = lmots_type

    def verify(self, message, sig):
        m, h, LenI = lms_params[self.lms_type]
        lms_type, q, lmots_sig, path = deserialize_lms_sig(sig)
        node_num = q + 2**h
        if lms_type != self.lms_type:
            return INVALID
        pathvalue = iter(path)
        tmp = lmots_sig_to_pub(lmots_sig, self.I + u32str(q), self.lmots_type, message)
        tmp = H(self.I + tmp + u32str(node_num) + D_LEAF)
        while node_num > 1:
            if (node_num % 2):
                 tmp = H(self.I + pathvalue.next() + tmp + u32str(node_num/2) + D_INTR)
            else:
                 tmp = H(self.I + tmp + pathvalue.next() + u32str(node_num/2) + D_INTR)
            node_num = node_num/2
        if (tmp == self.value):
            return VALID
        else:
            return INVALID

    def serialize(self):
        return u32str(self.lms_type) + u32str(self.lmots_type) + self.I + self.value

    @classmethod
    def parse(cls, buffer):
        lms_type = typecode_peek(buffer[0:4])
        if lms_type in lms_params:
            m, h, LenI = lms_params[lms_type]
        else:
            raise ValueError(err_unknown_typecode)
        return buffer[0:4+4+LenI+m], buffer[4+4+LenI+m:]

    @classmethod
    def deserialize(cls, buffer):
        lms_type = typecode_peek(buffer[0:4])
        if lms_type in lms_params:
            m, h, LenI = lms_params[lms_type]
        else:
            raise ValueError(err_unknown_typecode)
        lmots_type = typecode_peek(buffer[4:8])
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode)
        I = buffer[8:8+LenI]
        K = buffer[8+LenI:8+LenI+m]
        return cls(I, K, lms_type, lmots_type)
        
    def print_hex(self):
        PrintUtl.print_line()
        print "LMS public key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type), lms_name[self.lms_type])
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type), lmots_name[self.lmots_type])
        PrintUtl.print_hex("I", self.I)
        PrintUtl.print_hex("K", self.value)
        PrintUtl.print_line()


# ***************************************************************
#                                                               |
#             Hierarchical Signature System (HSS)               |
#                                                               |
# HSS signature format:                                         |
#   (l=number of signed_public_keys)                            |
#   array of l-2 signed_public_keys                             |
#   signature                                                   |
# ***************************************************************

def serialize_hss_sig(levels, publist, siglist, msg_sig):
    result = u32str(levels)
    for i in xrange(0, levels-1):
        result = result + siglist[i]
        result = result + publist[i+1].serialize()
    result = result + msg_sig
    return result

def deserialize_hss_sig(buffer):
    hss_max_levels = 8
    levels = deserialize_u32(buffer[0:4])
    if (levels > hss_max_levels):
        raise ValueError(err_bad_value)
    siglist = list()
    publist = list()
    tmp = buffer[4:]
    for i in xrange(0, levels-1):
        lms_sig, tmp = parse_lms_sig(tmp)
        siglist.append(lms_sig)
        lms_pub, tmp = LmsPublicKey.parse(tmp)
        publist.append(lms_pub)
    msg_sig = tmp
    return levels, publist, siglist, msg_sig


def print_hss_sig(sig):
    levels, publist, siglist, lms_sig = deserialize_hss_sig(sig)
    PrintUtl.print_line()
    print "HSS signature"
    PrintUtl.print_hex("L-1", u32str(levels))
    for i in xrange(0, levels-1):
        print "sig[" + str(i) + "]: " 
        print_lms_sig(siglist[i])
        print "pub[" + str(i) + "]: " 
        LmsPublicKey.deserialize(publist[i]).print_hex()
    print "final_signature: " 
    print_lms_sig(lms_sig)


class HssPrivateKey(object):
    """
    Hierarchical Signature System Private Key
    """
    def __init__(self, levels=2, lms_type=lms_sha256_m32_h5, lmots_type=lmots_sha256_n32_w8, prv0=None):
        self.levels = levels
        self.prv = list()
        self.pub = list()
        self.sig = list()
        if prv0 is None:
            prv0 = LmsPrivateKey(lms_type=lms_type, lmots_type=lmots_type)
        self.prv.append(prv0)
        self.pub.append(self.prv[0].get_public_key())
        for i in xrange(1, self.levels):
            self.prv.append(LmsPrivateKey(lms_type=lms_type, lmots_type=lmots_type))
            self.pub.append(self.prv[-1].get_public_key())
            self.sig.append(self.prv[-2].sign(self.pub[-1].serialize()))

    def sign(self, message):
        while (self.prv[-1].is_exhausted()):
            print "level " + str(len(self.prv)) + " is exhausted"
            if (len(self.prv) == 1):
                raise ValueError(err_private_key_exhausted)
            self.prv.pop()
            self.pub.pop()
            self.sig.pop()
        while (len(self.prv) < self.levels):
            print "refreshing level " + str(len(self.prv))
            self.prv.append(LmsPrivateKey(lms_type=self.prv[0].lms_type, lmots_type=self.prv[0].lmots_type))
            self.pub.append(self.prv[-1].get_public_key())
            self.sig.append(self.prv[-2].sign(self.pub[-1].serialize()))            

        # sign message 
        lms_sig = self.prv[-1].sign(message)
        return serialize_hss_sig(self.levels, self.pub, self.sig, lms_sig)    

    def get_public_key(self):
        return HssPublicKey(self.prv[0].get_public_key(), self.levels)

    def num_signatures_remaining(self):
        unused = self.prv[0].num_signatures_remaining()
        for i in xrange(1,self.levels):
            unused = unused * self.prv[i].max_signatures() + self.prv[i].num_signatures_remaining()            
        return unused

    def serialize(self):
        return u32str(self.levels) + self.prv[0].serialize()

    @classmethod
    def deserialize(cls, buffer):
        levels = deserialize_u32(buffer[0:4])
        prv = LmsPrivateKey.deserialize(buffer[4:])
        return cls(levels, lms_type=prv.lms_type, lmots_type=prv.lmots_type, prv0=prv)

    @classmethod
    def deserialize_print_hex(cls, buffer):
        """
        Parse all of the data elements of an HSS private key out of the string buffer.

        Does not initialize an hss_private_key (as that initialization computes at least one
        LMS public/private keypair, which can take a long time)

        :param buffer: string representing HSS private key
        :return:
        """
        PrintUtl.print_line()
        print "HSS private key"
        levels = deserialize_u32(buffer[0:4])
        PrintUtl.print_hex("levels", u32str(levels))
        print "prv[0]:"
        LmsPrivateKey.deserialize_print_hex(buffer[4:])
        PrintUtl.print_line()

    def print_hex(self):
        PrintUtl.print_line()
        print "HSS private key"
        PrintUtl.print_hex("levels", u32str(self.levels))
        for prv in self.prv:
            prv.print_hex()
        PrintUtl.print_line()

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for x in [ 1 ]: # lmots_params.keys():
            for y in [ 1 ]: # lms_params.keys():
                for l in [2,3]:
                    param_list.append({'lmots_type':x, 'lms_type':y, 'levels':l})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return HssPublicKey


class HssPublicKey(object):
    """
    Hierarchical Signature System Public Key
    """
    def __init__(self, rootpub, levels):
        self.pub1 = rootpub
        self.levels = levels

    def verify(self, message, sig):
        try:
            levels, publist, siglist, lms_sig = deserialize_hss_sig(sig)
            if levels != self.levels:
                return INVALID

            # verify the chain of signed public keys
            key = self.pub1
            for i in xrange(0, self.levels-1):
                sig = siglist[i]
                msg = publist[i]
                if (key.verify(msg, sig) != 1):
                    return INVALID
                key = LmsPublicKey.deserialize(msg)
            return key.verify(message, lms_sig)  

        except ValueError as err:
            if err.args[0] in err_list:
                return INVALID

    def serialize(self):
        return u32str(self.levels-1) + self.pub1.serialize()

    @classmethod
    def deserialize(cls, buffer):
        levels = deserialize_u32(buffer[0:4]) + 1
        rootpub = LmsPublicKey.deserialize(buffer[4:])
        return cls(rootpub, levels)

    def print_hex(self):
        PrintUtl.print_line()
        print "HSS public key"
        PrintUtl.print_hex("levels-1", u32str(self.levels-1))
        self.pub1.print_hex()
        PrintUtl.print_line()

# ***************************************************************
#                                                               |
#                       Test Functions                          |
#                                                               |
# ***************************************************************

def checksum_test():
    for typecode in [2]:
        n, p, w, ls = lmots_params[typecode]

        for j in xrange(0, n):
            x = ""
            for i in xrange(0,n):
                if i == j:
                    x = x + chr(0)
                else:
                    x = x + chr(0) 
            y = x + checksum(x, w, ls) 
            print "w: " + str(w) + "\tp: " + str(p) + "\tcksm: " + string_to_hex(checksum(x, w, ls))
            print "x + checksum(x): "
            print_as_coefs(y,w,p)
            print ""

def print_as_coefs(x, w, p):
    num_coefs = len(x)*(8/w)
    if (p > num_coefs):
        raise ValueError(err_bad_length)
    for i in xrange(0, p):
        print str(coef(x, i, w))
    print "\n"

# Message used in tests 
#
testmessage = "Hello, world!"

class byte_flip_mangler:
    def __init__(self, value):
        self.value = value
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        if self.i < len(self.value):
            i = self.i
            self.i += 1
            tmp = entropySource.read(1)
            while tmp == self.value[i]:
                tmp = entropySource.read(1)
            return self.value[:i] + tmp + self.value[i+1:]
        else:
            raise StopIteration()

class byte_snip_mangler:
    def __init__(self, value):
        self.value = value
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        if self.i < len(self.value):
            i = self.i
            self.i += 1
            return self.value[:i] + self.value[i+1:]
        else:
            raise StopIteration()

class mangler:
    def __init__(self, value):
        self.byte_flip = byte_flip_mangler(value)
        self.byte_snip = byte_snip_mangler(value)
    
    def __iter__(self):
        return self

    def next(self):
        try:
            return self.byte_flip.next()
        except StopIteration:
            return self.byte_snip.next()

def ntimesig_test(private_key_class, verbose=False):    
    paramlist = private_key_class.get_param_list()
    for param in paramlist:
        ntimesig_test_param(private_key_class, param, verbose) 

def ntimesig_test_param(private_key_class, param, verbose=False):
    """
    Unit test for N-time signatures

    :param param: dictionary containing private key parameters
    :param verbose: boolean that determines verbosity of output
    :return:
    """
    print "N-time signature test"
    public_key_class = private_key_class.get_public_key_class()
    private_key = private_key_class(**param)
    public_key_buffer = private_key.get_public_key().serialize() 
    public_key = public_key_class.deserialize(public_key_buffer) 
    num_sigs = private_key.num_signatures_remaining()
    numtests = min(num_sigs, 4096)
       
    if verbose:
        print "message: \"" + testmessage + "\""
        private_key.print_hex()
        public_key.print_hex()                
        print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())
        
    for i in xrange(0,numtests):
        sig = private_key.sign(testmessage)
        sigcopy = sig

        print "signature byte length: " + str(len(sig))
        if verbose:
            LmotsSignature.deserialize(sig).print_hex()
            print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())
        
        print "true positive test: ", 
        if (public_key.verify(testmessage, sig) == VALID):
            print "passed: message/signature pair is valid as expected"
        else:
            print "failed: message/signature pair is invalid"
            sys.exit()

        print "false positive test: ", 
        if (public_key.verify("some other message", sig) == VALID):
            print "failed: message/signature pair is valid (expected failure)"
            sys.exit(1)
        else:
            print "passed: message/signature pair is invalid as expected"

    print "overuse test: ", 
    print "num_sigs: " + str(num_sigs)
    if num_sigs < 1:
        print "error: private key reports that it is a zero-time signature system"
        sys.exit(1)
    for i in xrange(0,num_sigs):
        print "sign attempt #" + str(i)
        try:
            sig = private_key.sign("some other message")
        except ValueError as err:
            if err.args[0] == err_private_key_exhausted:
                print "passed: no overuse allowed"
            else:
                err_handle(err)
        else:
            if i > num_sigs:
                print "failed: key overuse occured; created " + str(i) + "signatures"
                sys.exit()

    print "mangled signature parse test",
    errdict = {}
    mangled_sig_iterator = mangler(sigcopy)
    for mangled_sig in mangled_sig_iterator:
        try:
            if (public_key.verify(testmessage, mangled_sig) == VALID):
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                public_key_class.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                errdict[err.args[0]] = errdict.get(err.args[0], 0) + 1
    print "error counts:"
    for errkey in errdict:
        print "\t" + errkey.ljust(40) + str(errdict[errkey])
    print "passed"
    
    print "mangled public key parse test",
    mangled_pub_iterator = mangler(public_key_buffer)
    errdict = {}
    for mangled_pub in mangled_pub_iterator:
        try:
            public_key = public_key_class.deserialize(mangled_pub)
            if (public_key.verify(testmessage, mangled_sig) == VALID):
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                LmotsSignature.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                errdict[err.args[0]] = errdict.get(err.args[0], 0) + 1
    print "error counts:"
    for errkey in errdict:
        print "\t" + errkey.ljust(40) + str(errdict[errkey])
    print "passed"

# ***************************************************************
#                                                               |
#                      File Processing                          |
#                                                               |
# ***************************************************************

def check_string(path):
    """
    Compute a check string based on the file path, which can be
    included in a file to make sure that the file has not been copied.
    This is useful because hash based signature private key files
    MUST NOT be copied.

    :param path: (not full) path of file
    :return: 32-byte check string 
    """
    return H(os.path.abspath(path))

def verify_check_string(path, buffer):
    """
    Verify that the first 32 bytes of buffer are a valid check string
    for path; if so, strip those bytes away and return the result.
    Otherwise, print and error and exit, to ensure that any private
    key file that makes use of this funciton will be protected against
    accidential overuse.
    """
    if buffer[0:32] != check_string(path):
        print "error: file \"" + path + "\" has been copied or modified"
        sys.exit(1)
    else:
        return buffer[32:]

# Implementation note: it might be useful to add in the last-modified
# time via os.path.getmtime(path), but it might be tricky to
# predict/control that value, especially in a portable way.
# Similarly, the output of uname() could be included.
    

# ***************************************************************
#                                                               |
#                        Main Program                           |
#                                                               |
# ***************************************************************


def usage(name):
    """
    Display the program usage options.

    :param name: Name of the file being executed
    :return:
    """
    print "commands:"
    print name + " genkey <name>"                                      
    print "   creates <name>.prv and <name>.pub"
    print ""
    print name + " sign <file> [ <file2> ... ] <prvname>"
    print "   updates <prvname>, then writes signature of <file> to <file>.sig"
    print ""
    print name + " verify <pubname> <file> [ <file2> ... ]"
    print "   verifies file using public key"
    print ""
    print name + " read <file> [ <file2> ... ]"
    print "   read and pretty-print .sig, .pub, .prv file(s)"
    print ""
    print name + " test [all | hss | lms | lmots | checksum ]"
    print "   performs algorithm tests"
    sys.exit(1)

if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] not in ["genkey", "sign", "verify", "read", "test"]:
        print "error: first argument must be a command (genkey, sign, verify, read, or test)"
        usage(sys.argv[0])
        sys.exit()

    if sys.argv[1] == "test":
        if len(sys.argv) == 2: 
            print "missing argument (expected checksum, lmots, lms, hss, or all)"
            usage(sys.argv[0])
            
        test_checksum = test_lmots = test_lms = test_hss = False
        if "checksum" in sys.argv[2:]:
            test_checksum = True
        if "lmots" in sys.argv[2:]:
            test_lmots = True
        if "lms" in sys.argv[2:]:
            test_lms = True
        if "hss" in sys.argv[2:]:
            test_hss = True
        if "all" in sys.argv[2:]:
            test_checksum = test_lmots = test_lms = test_hss = True

        if test_checksum:
            checksum_test()
        if test_lmots:
            ntimesig_test(LmotsPrivateKey, verbose=False)
        if test_lms:
            ntimesig_test(LmsPrivateKey, verbose=False)
        if test_hss:
            ntimesig_test(HssPrivateKey, verbose=False)

    if sys.argv[1] == "genkey":
        if len(sys.argv) >= 3:
            for keyname in sys.argv[2:]:
                print "generating key " + keyname            
                hss_prv = HssPrivateKey()
                hss_pub = hss_prv.get_public_key()
                prv_file = open(keyname + ".prv", 'w')
                prv_file.write(check_string(keyname + ".prv") + hss_prv.serialize())
                pub_file = open(keyname + ".pub", 'w')
                pub_file.write(hss_pub.serialize())
        else:
            print "error: missing keyname argument(s)\n"
            usage()
            
    if sys.argv[1] == "sign":
        keyname = None
        msgnamelist = list()
        for f in sys.argv[2:]:
            if ".prv" in f:
                if keyname is not None:
                    print "error: too many private keys given on command line"
                keyname = f
            else:
                msgnamelist.append(f)
        if keyname is None:
            print "error: no private key given on command line"
            usage(sys.argv[0])
        if len(msgnamelist) is 0:
            print "error: no messages given on command line"
            usage(sys.argv[0])
        prv_file = open(keyname, "r+")
        prv_buf = prv_file.read()
        hss_prv = HssPrivateKey.deserialize(verify_check_string(keyname, prv_buf))
        for msgname in msgnamelist:
            print "signing file " + msgname + " with key " + keyname            
            msgfile = open(msgname, 'r')
            msg = msgfile.read()
            tmpsig = hss_prv.sign(msg)
            prv_file.seek(0)
            prv_file.write(check_string(keyname) + hss_prv.serialize())
            prv_file.truncate()
            sig = open(msgname + ".sig", "w")
            sig.write(tmpsig)

    if sys.argv[1] == "verify":
        pubname = None
        msgnamelist = list()
        for f in sys.argv[2:]:
            if ".pub" in f:
                if pubname is not None:
                    print "error: too many public keys given on command line"
                    usage(sys.argv[0])
                pubname = f
            else:
                msgnamelist.append(f)
        if pubname is None:
            print "error: no public key given on command line"
            usage(sys.argv[0])
        if len(msgnamelist) is 0:
            print "error: no file(s) to be verified given on command line"
            usage(sys.argv[0])
        pubfile = open(pubname, 'r')
        pub = HssPublicKey.deserialize(pubfile.read())
        for msgname in msgnamelist:
            signame = msgname + ".sig"
            print "verifying signature " + signame + " on file " + msgname + " with pubkey " + pubname
            sigfile = open(signame, 'r')
            sig = sigfile.read()
            msgfile = open(msgname, 'r')
            msg = msgfile.read()
            if (pub.verify(msg, sig) == 1):
                print "VALID"
            else:
                print "INVALID"

    if sys.argv[1] == "read":
        if (len(sys.argv) < 3):
            print 'error: expecting filename(s) after "read" command'
            usage(sys.argv[0])

        for f in sys.argv[2:]:
            file = open(f, 'r')
            buf = file.read()
            if ".sig" in f:
                print_hss_sig(buf)
            elif ".pub" in f:
                HssPublicKey.deserialize(buf).print_hex()
            elif ".prv" in f:
                # strip check string from start of buffer
                HssPrivateKey.deserialize_print_hex(buf[32:]) 
