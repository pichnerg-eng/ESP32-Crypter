#ifndef CRYPTOCONFIG_H
#define CRYPTOCONFIG_H


//==================================================
// Crypto paraméterek
//==================================================

#define VERSION_LEN       1
#define MESSAGE_ID_LEN    2

#define SALT_LEN          16
#define IV_LEN            12
#define TAG_LEN           16

#define KEY_LEN           32

#define CRYPTO_MAX_MESSAGE_SIZE 128



//==================================================
// Packet fejléc mérete
//
// VERSION
// MESSAGE_ID
// SALT
// IV
// TAG
//
//==================================================

#define PACKET_HEADER_LEN \
    (VERSION_LEN + MESSAGE_ID_LEN + SALT_LEN + IV_LEN + TAG_LEN)


#endif