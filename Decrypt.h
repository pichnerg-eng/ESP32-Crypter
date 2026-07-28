#ifndef DECRYPT_H
#define DECRYPT_H


#include <Arduino.h>
#include "CryptoConfig.h"


struct CryptoMessage
{
    uint8_t version;
    uint16_t messageID;
    String text;
};



class Decrypt
{

public:

    Decrypt();


    bool begin(
        const char *password);


    bool decryptBase64(
        const char *encoded,
        CryptoMessage &result);



private:

    const char *_password;



    bool deriveKey(
        const uint8_t *salt,
        uint8_t *key);



    bool decryptAESGCM(
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *ciphertext,
        size_t cipherLen,
        const uint8_t *tag,
        uint8_t *plaintext);



    size_t decodeBase64(
        const char *input,
        uint8_t *output,
        size_t outputSize);


    bool parsePacket(
        uint8_t *packet,
        size_t packetLen,
        uint8_t &version,
        uint16_t &messageID,
        uint8_t *salt,
        uint8_t *iv,
        uint8_t *tag,
        uint8_t *ciphertext,
        size_t &cipherLen);

};


#endif
