#include "Decrypt.h"

#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"


//==================================================
// Konstruktor
//==================================================

Decrypt::Decrypt()
{
    _password = nullptr;
}


//==================================================
// Jelszó beállítása
//==================================================

bool Decrypt::begin(
    const char *password)
{
    _password = password;
    return true;
}


//==================================================
// PBKDF2 kulcsszármaztatás
//==================================================

bool Decrypt::deriveKey(
    const uint8_t *salt,
    uint8_t *key)

{
    int ret =
        mbedtls_pkcs5_pbkdf2_hmac_ext(
            MBEDTLS_MD_SHA256,
            (const unsigned char *)_password,
            strlen(_password),
            salt,
            SALT_LEN,
            10000,
            KEY_LEN,
            key
        );

    return (ret == 0);
}


//==================================================
// Base64 dekódolás
//==================================================

size_t Decrypt::decodeBase64(
    const char *input,
    uint8_t *output,
    size_t outputSize)

{
    size_t outputLen = 0;


    int ret =
        mbedtls_base64_decode(
            output,
            outputSize,
            &outputLen,
            (const unsigned char *)input,
            strlen(input)
        );


    if(ret != 0)
    {
        return 0;
    }


    return outputLen;
}


//==================================================
// Packet bontás
//
// VERSION
// MESSAGE_ID
// SALT
// IV
// TAG
// CIPHERTEXT
//
//==================================================

bool Decrypt::parsePacket(
    uint8_t *packet,
    size_t packetLen,
    uint8_t &version,
    uint16_t &messageID,
    uint8_t *salt,
    uint8_t *iv,
    uint8_t *tag,
    uint8_t *ciphertext,
    size_t &cipherLen)

{

    if(packetLen < PACKET_HEADER_LEN)
    {
        return false;
    }


    size_t offset = 0;


    // VERSION

    version = packet[offset];

    offset += VERSION_LEN;



    // MESSAGE ID

    messageID =
        ((uint16_t)packet[offset] << 8)
        |
        packet[offset + 1];

    offset += MESSAGE_ID_LEN;



    // SALT

    memcpy(
        salt,
        packet + offset,
        SALT_LEN
    );

    offset += SALT_LEN;



    // IV

    memcpy(
        iv,
        packet + offset,
        IV_LEN
    );

    offset += IV_LEN;



    // TAG

    memcpy(
        tag,
        packet + offset,
        TAG_LEN
    );

    offset += TAG_LEN;



    // CIPHER

    cipherLen =
        packetLen - offset;


    if(cipherLen > CRYPTO_MAX_MESSAGE_SIZE)
    {
        return false;
    }


    memcpy(
        ciphertext,
        packet + offset,
        cipherLen
    );


    return true;
}


//==================================================
// AES-GCM visszafejtés
//==================================================

bool Decrypt::decryptAESGCM(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *ciphertext,
    size_t cipherLen,
    const uint8_t *tag,
    uint8_t *plaintext)

{

    mbedtls_gcm_context gcm;


    mbedtls_gcm_init(&gcm);



    int ret =
        mbedtls_gcm_setkey(
            &gcm,
            MBEDTLS_CIPHER_ID_AES,
            key,
            256
        );


    if(ret != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }



    ret =
        mbedtls_gcm_auth_decrypt(
            &gcm,
            cipherLen,
            iv,
            IV_LEN,
            NULL,
            0,
            tag,
            TAG_LEN,
            ciphertext,
            plaintext
        );


    mbedtls_gcm_free(&gcm);


    return (ret == 0);
}


//==================================================
// Teljes decrypt folyamat
//
// Base64
//    |
//    v
// Packet bontás
//    |
//    v
// Kulcsszármaztatás
//    |
//    v
// AES-GCM decrypt
//
//==================================================

bool Decrypt::decryptBase64(
    const char *encoded,
    CryptoMessage &result)

{

    uint8_t packet[256];

    size_t packetLen =
        decodeBase64(
            encoded,
            packet,
            sizeof(packet)
        );


    if(packetLen == 0)
    {
        return false;
    }



    uint8_t version;

    uint16_t messageID;


    uint8_t salt[SALT_LEN];

    uint8_t iv[IV_LEN];

    uint8_t tag[TAG_LEN];

    uint8_t ciphertext[CRYPTO_MAX_MESSAGE_SIZE];


    size_t cipherLen;



    if(!parsePacket(
            packet,
            packetLen,
            version,
            messageID,
            salt,
            iv,
            tag,
            ciphertext,
            cipherLen))
    {
        return false;
    }



    uint8_t key[KEY_LEN];


    if(!deriveKey(
            salt,
            key))
    {
        return false;
    }



    uint8_t plaintext[CRYPTO_MAX_MESSAGE_SIZE + 1];


    if(!decryptAESGCM(
            key,
            iv,
            ciphertext,
            cipherLen,
            tag,
            plaintext))
    {
        return false;
    }



    plaintext[cipherLen] = 0;



    //==============================================
    // Visszaadott adatok
    //==============================================

    result.version = version;

    result.messageID = messageID;


    result.text =
        String(
            (char*)plaintext
        );


    return true;
}