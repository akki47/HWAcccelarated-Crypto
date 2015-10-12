#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <openssl/conf.h>
#ifndef CRYPTO_H
#define CRYPTO_H
#define RSA_KEYLEN 2048
#define AES_KEYLEN 128
#define AES_ROUNDS 6
#define PSUEDO_CLIENT
//#define USE_PBKDF
#define SUCCESS 0
#define FAILURE -1
#define KEY_SERVER_PRI 0
#define KEY_SERVER_PUB 1
#define KEY_CLIENT_PUB 2
#define KEY_CLIENT_PRI 5
#define KEY_AES 3
#define KEY_AES_IV 4


#define TIMESTAMP_LENGTH 24
#define PROTOCOL_ID_LENGTH 5
#define MACHINE_ID_LENGTH 5
#define LOG_FILE_ID_LENGTH 1
#define LOG_ENTRY_TYPE_LENGTH 5
#define MAX_LOGFILES 5
#define Z_0_LENGTH 32
#define Y_0_LENGTH 32

class Crypto {
public:
Crypto();
Crypto(unsigned char *remotePubKey, size_t remotePubKeyLen);
~Crypto();

int rsaEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl);
int aesEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg);
int rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl, unsigned char *iv, size_t ivl, unsigned char **decMsg);
int aesDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg);
int writeKeyToFile(FILE *fd, int key);
int getRemotePubKey(unsigned char **pubKey);
int setRemotePubKey(unsigned char *pubKey, size_t pubKeyLen);
int getLocalPubKey(unsigned char **pubKey);
int getLocalPriKey(unsigned char **priKey);
int getAESKey(unsigned char **aesKey);
int setAESKey(unsigned char *aesKey, size_t aesKeyLen);
int getAESIv(unsigned char **aesIv);
int setAESIv(unsigned char *aesIv, size_t aesIvLen);
int hash(unsigned char *encMsg,  size_t encMsgLen,unsigned char *encMsg2,  size_t encMsg2Len, unsigned char digest[], unsigned int md_len);
int hash(unsigned char *encMsg,  size_t encMsgLen, unsigned char digest[], unsigned int md_len);
int hash(unsigned char *encMsg,  size_t encMsgLen,unsigned char *encMsg2,  size_t encMsg2Len,unsigned char *encMsg3,  size_t encMsg3Len, unsigned char digest[], unsigned int md_len);
int sign(unsigned char *encMsg,  size_t encMsgLen, unsigned char sig_buf[], unsigned int sig_len );
int verify(unsigned char *encMsg,  size_t encMsgLen,unsigned char sig_buf[], unsigned int sig_len );
int sign_alt(unsigned char *encMsg,  size_t encMsgLen, unsigned char sig_buf[], unsigned int sig_len );
int verify_alt(unsigned char *encMsg,  size_t encMsgLen,unsigned char sig_buf[], unsigned int sig_len );
int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int hmac(unsigned char *encMsg,  size_t encMsgLen,unsigned char *key, int key_length, unsigned char digest[], unsigned int md_len);
int sign_alt(unsigned char *msg_s, unsigned int msg_s_length,  unsigned char *sig_s, unsigned int sig_len_s,EVP_MD_CTX *mdctx);
int verify_alt(EVP_MD_CTX *mdctx,unsigned char *msg_s, unsigned int msg_s_length, unsigned char *sig_s, unsigned int sig_len_s);
private:
static EVP_PKEY *localKeypair;
EVP_PKEY *remotePubKey;
EVP_CIPHER_CTX *rsaEncryptCtx;
EVP_CIPHER_CTX *aesEncryptCtx;
EVP_CIPHER_CTX *rsaDecryptCtx;
EVP_CIPHER_CTX *aesDecryptCtx;
unsigned char *aesKey;
unsigned char *aesIV;

int init();
int genTestClientKey();
};
#endif
