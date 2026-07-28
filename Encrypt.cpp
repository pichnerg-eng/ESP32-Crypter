#include "Encrypt.h"

#include <esp_system.h>

#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"

//==================================================
// Konstruktor
//==================================================

Encrypt::Encrypt()
{
    _password = nullptr;
}

//==================================================
// Jelszó beállítása
//==================================================

bool Encrypt::begin(
    const char *password)

{
    _password = password;
    return true;
}



//==================================================
// PBKDF2 kulcsszármaztatás
//==================================================

bool Encrypt::deriveKey(
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
// AES-256-GCM titkosítás
//==================================================

bool Encrypt::encryptAESGCM(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *plaintext,
    size_t plaintextLen,
    uint8_t *ciphertext,
    uint8_t *tag)

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
        mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            plaintextLen,
            iv,
            IV_LEN,
            NULL,
            0,
            plaintext,
            ciphertext,
            TAG_LEN,
            tag
        );



    mbedtls_gcm_free(&gcm);



    return (ret == 0);
}



//==================================================
// Packet összeállítás
//
// VERSION
// MESSAGE_ID
// SALT
// IV
// TAG
// CIPHERTEXT
//
//==================================================

bool Encrypt::buildPacket(
    uint8_t version,
    uint16_t messageID,
    const uint8_t *salt,
    const uint8_t *iv,
    const uint8_t *tag,
    const uint8_t *ciphertext,
    size_t cipherLen,
    uint8_t *packet)

{

    size_t offset = 0;



    // VERSION

    packet[offset++] = version;



    // MESSAGE ID

    packet[offset++] =
        (messageID >> 8) & 0xFF;

    packet[offset++] =
        messageID & 0xFF;



    // SALT

    memcpy(
        packet + offset,
        salt,
        SALT_LEN
    );

    offset += SALT_LEN;



    // IV

    memcpy(
        packet + offset,
        iv,
        IV_LEN
    );

    offset += IV_LEN;



    // TAG

    memcpy(
        packet + offset,
        tag,
        TAG_LEN
    );

    offset += TAG_LEN;



    // DATA

    memcpy(
        packet + offset,
        ciphertext,
        cipherLen
    );


    return true;
}



//==================================================
// Base64 kódolás
//==================================================

String Encrypt::encodeBase64(
    const uint8_t *data,
    size_t len)

{

    size_t outputLen = 0;


    size_t bufferSize =
        ((len + 2) / 3) * 4 + 1;



    unsigned char *buffer =
        new unsigned char[bufferSize];



    int ret =
        mbedtls_base64_encode(
            buffer,
            bufferSize,
            &outputLen,
            data,
            len
        );



    if(ret != 0)
    {
        delete[] buffer;
        return "";
    }



    String result =
        String((char *)buffer);



    delete[] buffer;



    return result;
}



//==================================================
// ÚJ FŐ TITKOSÍTÓ FUNKCIÓ
//
// Üzenet -> AES-GCM -> Raw packet + Base64
//
//==================================================

bool Encrypt::encrypt(
    const char *message,
    uint16_t messageID,
    uint8_t version,
    CryptoPacket &result)

{

    uint8_t salt[SALT_LEN];

    uint8_t iv[IV_LEN];

    uint8_t key[KEY_LEN];

    uint8_t ciphertext[CRYPTO_MAX_MESSAGE_SIZE];

    uint8_t tag[TAG_LEN];



    // Véletlen Salt

    esp_fill_random(
        salt,
        SALT_LEN
    );



    // Véletlen IV

    esp_fill_random(
        iv,
        IV_LEN
    );



    // Kulcs előállítás

    if(!deriveKey(
            salt,
            key))
    {
        return false;
    }



    // AES titkosítás

    if(!encryptAESGCM(
            key,
            iv,
            (uint8_t *)message,
            strlen(message),
            ciphertext,
            tag))
    {
        return false;
    }



    // Metaadat visszaadás

    result.version = version;

    result.messageID = messageID;



    // Raw packet készítés

    buildPacket(
        version,
        messageID,
        salt,
        iv,
        tag,
        ciphertext,
        strlen(message),
        result.raw
    );



    result.rawLength =
        PACKET_HEADER_LEN +
        strlen(message);



    // Base64

    result.base64 =
        encodeBase64(
            result.raw,
            result.rawLength
        );



    return true;
}



//==================================================
// Régi kompatibilis függvény
//
// Csak Base64 eredményt ad vissza
//
//==================================================

String Encrypt::encryptBase64(
    const char *message,
    uint16_t messageID,
    uint8_t version)

{

    CryptoPacket packet;


    if(!encrypt(
            message,
            messageID,
            version,
            packet))
    {
        return "";
    }



    return packet.base64;
}