#!/usr/bin/env python
"""
COMP3109 final project. By David Barrera

With contributions from Discord users:
clark
Always
Ynnad00
Kushaforei
Breezy
Andyimo
EnderTheNetrunner
nicman

COMP3109 final project COMPLETED. By Kenji Isak Laguan 101160737
"""
import nacl
import nacl.secret
import nacl.utils
from nacl.hash import blake2b
from nacl.public import PrivateKey,SealedBox
from nacl.signing import SigningKey,VerifyKey


import tink
from tink import aead
from tink import hybrid
from tink import signature
from tink import mac

def generateSecretKeyNacl():
    """
    Generates a random symmetric key using nacl
    
    Returns:
        key (bytes)
    """
    key = nacl.utils.random(nacl.secret.Aead.KEY_SIZE)
    return key

def generateSecretKeyTink():
    """
    Generates a random symmetric key using Tink.

    Notes:
        Use the AEAD primitive.
        Use the AES256_GCM key template
    Returns:
        keyset_handle (KeysetHandle)
    """
    aead.register()
    # keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.XCHACHA20_POLY1305) # test for compatibility remember to change back!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # keysethandle = tink.KeysetHandle.generate_new(aead.aead_key_templates.AES256_GCM) # works as well
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    primitive = keyset_handle.primitive(aead.Aead) # dont know why we need to use this when we dont
    return keyset_handle

def aeadEncryptNacl(key, message, associated_data, nonce):
    """
    Encrypts plaintext string "message" and associate data "aad" using key and a 24 byte nonce. Uses AEAD
    
    Notes: this function should return a ciphertext to be used as the first parameter of aeadDecryptNacl() below. 
    Parameters:
        key (bytes)
        message (string)
        associated_data (bytes)
        nonce (bytes)
        
    Returns:
        ciphertext (bytes)
    """
    box = nacl.secret.Aead(key) # uses Aead for aad
    encrypted = box.encrypt(str.encode(message),associated_data,nonce) # encrypts with authentication data of MAC
    ciphertext = encrypted.ciphertext # ciphertext + MAC, no nonce
    return ciphertext

def aeadDecryptNacl(ciphertext, associated_data, key, nonce):
    """
    Decrypts a ciphertext using associated_data, key and nonce
    
    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        key (bytes)
        nonce (bytes)
    Returns:
        message (string)
    """
    box = nacl.secret.Aead(key)
    message = box.decrypt(ciphertext,associated_data,nonce)
    message = message.decode('utf-8')
    return message

def aeadEncryptTink(keyset_handle, message, associated_data):
    """
    Encrypts plaintext message and associated data using XCHACHA20-POLY1305 and a provided keyset handle.

    Notes: 
        Function must ensure that the keyset handle is compatible with XCHACHA20-POLY1305. Should return a ciphertext that can be passed as the first parameter of aeadDecryptTink() below. 
    Parameters:
        keyset_handle (KeysetHandle)
        message (string)
        associated_data (bytes)
    Returns:
        ciphertext (bytes)
    """
    
    aead.register()
    keytype = keyset_handle.keyset_info().key_info[0].type_url # grabs the type
    xcha = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"

    if (keytype != xcha): # if keyset handle isnt compatible with xchacha return None
        return None
    primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(str.encode(message),associated_data)
    return ciphertext

def aeadDecryptTink(ciphertext, associated_data, keyset_handle):
    """
    Decrypts a ciphertext using the keyset handle and associated data

    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """
    aead.register()
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = primitive.decrypt(ciphertext,associated_data)
    plaintext = plaintext.decode('utf-8')
    return plaintext
    
def generateKeyPairNacl():
    """
    Uses NaCl to generate a public/private key pair

    Returns: 
        Returns tuple of Curve25519 keys:
            privkey (PrivateKey)
            pubkey (PublicKey)
    """
    privkey = PrivateKey.generate()
    pubkey = privkey.public_key
    return privkey,pubkey

def generateHybridEncryptionKeyPairTink():
    """
    Uses Tink to generate a keypair suitable for hybrid encryption
    
    Notes:
        Keys must use the ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 hybrid key template
    Returns:
        Tuple of keyset handles 
            private_keyset_handle (KeysetHandle)
            public_keyset_handle (KeysetHandle)
    """
    hybrid.register()
    private_keyset_handle = tink.new_keyset_handle(hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256)
    public_keyset_handle = private_keyset_handle.public_keyset_handle()
    return private_keyset_handle,public_keyset_handle

def hybridEncryptNacl(message, pubkey):
    """
    Uses the public key to encrypt a random symmetric key, and then encrypts message using that symmetric key. MUST NOT ENCRYPT USING PUBKEY DIRECTLY!
    
    Notes: The returned ciphertext and encrypted_symmetric_key should be compatible with the hybridDecryptNacl() below. 
    Parameters:
        message (string)
        pubkey (PublicKey)
    Returns:
        Tuple containing:
            ciphertext (bytes)
            encrypted_symmetric_key (bytes)
    """
    symmetrickey = generateSecretKeyNacl() # generate random symmetric key
    nonce = nacl.utils.random(nacl.secret.Aead.NONCE_SIZE)

    box = nacl.secret.Aead(symmetrickey) # uses Aead for aad
    ciphertext = box.encrypt(str.encode(message),b"aad",nonce) # encrypts with authentication data of MAC
    
    sealedbox = SealedBox(pubkey) # public key encryption wihtout the use of privkey
    encrypted_symmetric_key = sealedbox.encrypt(symmetrickey)
    return ciphertext,encrypted_symmetric_key

def hybridDecryptNacl(ciphertext, encrypted_key, privkey):
    """
    Uses the private key to first decrypt the shared symmetric key (generated in hybridEncryptNacl). Uses the symmetric key to decrypt the ciphertext. 
    
    Parameters:
        ciphertext (bytes)
        encrypted_symmetric_key (bytes)
        privkey (PrivateKey)
    
    Returns plaintext (string)
    """
    unsealbox = SealedBox(privkey)
    symmetrickey = unsealbox.decrypt(encrypted_key)

    nonce = ciphertext[:nacl.secret.Aead.NONCE_SIZE] # grabs nonce from ciphertext first 24 bytes
    
    ciphertext = ciphertext[nacl.secret.Aead.NONCE_SIZE:] # grabs ciphertext from ciphertext past 24 bytes
    plaintext = aeadDecryptNacl(ciphertext,b"aad",symmetrickey,nonce)
    return plaintext

def hybridEncryptTink(message, associated_data, public_keyset_handle):
    """
    Uses Tink to perform hybrid encryption on a plaintext message and associated data, and uses a public keyset handle to obtain the public key to use. 
    
    Notes: The ciphertext should be compatible as the first parameter of the hybridDecryptTink() function below.
    Parameters:
        message (string)
        associated_data (bytes)
        public_keyset_handle (KeysetHandle)
    Returns:
        ciphertext (bytes)
    """
    hybrid_encrypt = public_keyset_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_encrypt.encrypt(str.encode(message),associated_data)
    return ciphertext

def hybridDecryptTink(ciphertext, associated_data, private_keyset_handle):
    """
    Decrypts ciphertext using private key. Requires passing associated_data for authentication. 

    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        private_keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """
    hybrid_decrypt = private_keyset_handle.primitive(hybrid.HybridDecrypt)
    plaintext = hybrid_decrypt.decrypt(ciphertext,associated_data)
    plaintext = plaintext.decode('utf-8')
    return plaintext

def generateSignatureKeypairNacl():
    """
    Generates a signing key and a verification key using Nacl

    Returns: 
        Tuple of keys
            sigkey (SigningKey)
            verifykey (VerifyKey)
    """
    sigkey = SigningKey.generate()
    verifykey = sigkey.verify_key
    return sigkey,verifykey

def generateSignatureKeypairTink():
    """
    Generates a signing key and verification key using Tink.
    
    Notes: must use the ECDSA_P384 signature key template
    Returns:
        Tuple of keyset handles 
            signing_keyset_handle (KeysetHandle)
            verify_keyset_handle (KeysetHandle)
    """
    signature.register()

    signing_keyset_handle = tink.new_keyset_handle(signature.signature_key_templates.ECDSA_P384)
    verify_keyset_handle = signing_keyset_handle.public_keyset_handle()

    return signing_keyset_handle, verify_keyset_handle

def signNacl(message, sigkey):
    """
    Uses NaCl to digitally sign a message using sigkey
    
    Notes: Should only return the signature data, not the message+signature. The retured signature should be compatible with the tag parameter of the verifyNacl() method.
    Parameters:
        message (string)
        sigkey (SigningKey)
    
    Returns:
        signature (bytes)
    """
    signed = sigkey.sign(str.encode(message)) # signs message 
    signature = signed.signature    # grabs just the signature as its SignedMessage class
    return signature


def signTink(message, signing_keyset_handle):
    """
    Digitally signs message using signing key in signing_keyset_handle
    
    Notes: Only return the signature, do not return the message. The signature should be compatible with the signature_data parameter of the verifyTink() method.
    Parameters:
        message (string)
        signing_keyset_handle (KeysetHandle)
    Returns:
        signature (bytes). 
    """
    signature.register()
    signer = signing_keyset_handle.primitive(signature.PublicKeySign) # get primitive
    signed = signer.sign(str.encode(message)) # signature data, confirmed by looking at source code through github, and printing doesnt show the message
    return signed

def verifyNacl(message, tag, verifykey):
    """
    Verify the signature tag on a message using the verification key
    
    Parameters:
        message (string)
        tag (bytes)
        verifykey (VerifyKey)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """
    verifykey = VerifyKey(verifykey.encode()) # serialize the vkey by encoding it then creating a VerifyKey object with it
    while True:
        try:
            verifykey.verify(str.encode(message),tag) # verifies signature, if no errors, break and return true 
            break
        except: # if an error gets thrown which means something failed, return false
            verification_status = False
            return verification_status # can use nacl.exceptions.BadSignatureError error as well to be specific to signature failed, but well handle for all errors as a fail
    verification_status = True
    return verification_status

def verifyTink(message, signature_data, verifying_keyset_handle):
    """
    Verify the signature on a message using the verifying keyset handle

    Parameters:
        message (string)
        signature_data (bytes)
        verifying_keyset_handle (KeysetHandle)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """    
    verifier = verifying_keyset_handle.primitive(signature.PublicKeyVerify)
    while True:
        try:
            verifier.verify(signature_data,str.encode(message)) # verifies signature, if no errors, break and return true 
            break
        except: # if an error gets thrown which means something failed, return false
            verification_status = False
            return verification_status 
    verification_status = True
    return verification_status
    
def computeMacNacl(message, key):
    """
    Computes a MAC using the provided key
    
    Notes: Use blake2b. Should be compatible with the verify method below. 
    Parameters:
        message (string)
        key (bytes)
    Returns:
        tag (bytes)
    """
    tag = blake2b(str.encode(message),key=key)
    return tag

def verifyMacNacl(message, tag, key):
    """
    Verifies whether the provided MAC tag is correct for the message and key
    
    Parameters:
        message (string)
        tag (bytes)
        key (bytes)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    verifymac = blake2b(str.encode(message),key=key)
    if (verifymac == tag): # if theyre the same hashes/same tag
        verified = True
        return verified
    else:
        verified = False
        return verified

def computeMacTink(message, mac_keyset_handle):
    """
    Computes a MAC on the message using the provided keyset handle 
    
    Notes: The returned tag should be compatible with the verifyMacTink() method below.
    Parameters:
        message (string)
        mac_keyset_handle (KeysetHandle)
    Returns: 
        tag (bytes)
    """
    mac.register()
    primitive = mac_keyset_handle.primitive(mac.Mac)
    tag = primitive.compute_mac(str.encode(message))
    return tag

def verifyMacTink(message, tag, mac_keyset_handle):
    """
    Verifies a mac using the provided tag and keyset handle
    
    Parameters:
        message (string)
        tag (bytes)
        mac_keyset_handle (KeysetHandle)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    mac.register()
    primitive = mac_keyset_handle.primitive(mac.Mac)
    while True:
        try:
            primitive.verify_mac(tag,str.encode(message)) # verifies signature, if no errors, break and return true 
            break
        except: # if an error gets thrown which means something failed, return false
            verified = False
            return verified 
    verified = True
    return verified

if __name__ == '__main__':
    print("NACL Key:",generateSecretKeyNacl())
    print("TINK Key:",generateSecretKeyTink())

    key = generateSecretKeyNacl()
    naclnonce = nacl.utils.random(nacl.secret.Aead.NONCE_SIZE)
    ciphertext = aeadEncryptNacl(key,"nacl",b"aad",naclnonce)
    print("\nNACL Encrypt:",ciphertext)
    print("NACL Decrypt:",aeadDecryptNacl(ciphertext,b"aad",key,naclnonce))

    tinkkeyaes = generateSecretKeyTink()
    tinkcipheraes = aeadEncryptTink(tinkkeyaes,"tinkaes",b"aad")
    print("\nTINK Encrypt AES:",tinkcipheraes)


    tinkkeycha = tink.new_keyset_handle(aead.aead_key_templates.XCHACHA20_POLY1305)
    tinkciphercha = aeadEncryptTink(tinkkeycha,"tinkxcha",b"aad")
    print("\nTINK Encrypt XCHA:",tinkciphercha)
    print("TINK Decrypt XCHA:",aeadDecryptTink(tinkciphercha,b"aad",tinkkeycha))

    print("\nNACL Keypair:",generateKeyPairNacl())
    print("TINK Keypair:",generateHybridEncryptionKeyPairTink())

    naclkeypair = generateKeyPairNacl()
    privkey = naclkeypair[0]
    pubkey = naclkeypair[1]
    
    hybridnacl = hybridEncryptNacl("hybridnacl", pubkey)
    hybridnaclcipher = hybridnacl[0]
    hybridnaclkey = hybridnacl[1]

    print("\nNACL Hybrid Cipher: ",hybridnaclcipher)
    print("NACL Hybrid Symmetric Key: ",hybridnaclkey)
    print("NACL Hybrid Decrypt: ",hybridDecryptNacl(hybridnaclcipher, hybridnaclkey,privkey))

    tinkkeypair = generateHybridEncryptionKeyPairTink()
    tinkprivkeyhandle = tinkkeypair[0]
    tinkpubkeyhandle = tinkkeypair[1]

    hybridtink = hybridEncryptTink("hybridtink",b"aad",tinkpubkeyhandle)
    print("\nTINK Hybrid Encrypt:",hybridtink)
    print("TINK Hybrid Decrypt:",hybridDecryptTink(hybridtink,b"aad",tinkprivkeyhandle))

    print("\nNACL Signature Keypair:", generateSignatureKeypairNacl())
    print("TINK Signature Keypair:", generateSignatureKeypairTink())
    
    print("\nNACL Sign: ", signNacl("NaclSign",generateSignatureKeypairNacl()[0]))
    print("TINK Sign: ", signTink("TinkSign",generateSignatureKeypairTink()[0]))

    signkpairnacl = generateSignatureKeypairNacl()
    signkeynacl = signkpairnacl[0]
    verifykeynacl = signkpairnacl[1]
    tagnacl = signNacl("VerifyNacl",signkeynacl)
    print("\nNACL Verify: ", verifyNacl("VerifyNacl",tagnacl,verifykeynacl))
    
    signkpairtink = generateSignatureKeypairTink()
    signkeytink = signkpairtink[0]
    verifykeytink = signkpairtink[1]
    sigdatatink = signTink("VerifyTink",signkeytink)
    print("TINK Verify: ", verifyTink("VerifyTink",sigdatatink,verifykeytink))

    mackeynacl = generateSecretKeyNacl()
    tagnacl = computeMacNacl("Macnacl",mackeynacl)
    print("\nNACL Mac:",tagnacl)
    print("NACL Mac Verify:", verifyMacNacl("Macnacl",tagnacl,mackeynacl))

    mac.register()
    mackeytink = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA512_256BITTAG)
    tagtink = computeMacTink("Mactink",mackeytink)
    print("\nTINK Mac:",tagtink)
    print("TINK Mac Verify:", verifyMacTink("Mactink",tagtink,mackeytink))