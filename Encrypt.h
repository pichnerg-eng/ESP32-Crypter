#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <Arduino.h>
#include "CryptoConfig.h"


struct CryptoPacket
{
    uint8_t version;
    uint16_t messageID;
    uint8_t raw[256];
    size_t rawLength;
    String base64;
};

class Encrypt
{

public:

    Encrypt();


    bool begin(
        const char *password
    );


String encryptBase64(
    const char *message,
    uint16_t messageID = 0,
    uint8_t version = 1);

bool encrypt(
    const char *message,
    uint16_t messageID,
    uint8_t version,
    CryptoPacket &result);



private:

    const char *_password;


    bool deriveKey(
        const uint8_t *salt,
        uint8_t *key);


    bool encryptAESGCM(
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *plaintext,
        size_t plaintextLen,
        uint8_t *ciphertext,
        uint8_t *tag);

   
    bool buildPacket(
        uint8_t version,
        uint16_t messageID,
        const uint8_t *salt,
        const uint8_t *iv,
        const uint8_t *tag,
        const uint8_t *ciphertext,
        size_t cipherLen,
        uint8_t *packet);


    String encodeBase64(
        const uint8_t *data,
        size_t len);


};


#endif