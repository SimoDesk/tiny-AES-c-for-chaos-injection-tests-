#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// GCM enables encryption in Galois counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif

#ifndef GCM
  #define GCM 1
#endif


//#define AES128 1
//#define AES192 1
#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define AES_IVLEN 12 // IV length in bytes 

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)


#if defined(GCM) && (GCM == 1)

#define GCM_TAGLEN 16 // Tag length in bytes - GCM is 128b tag only
#define AAD_LENGTH 16 // Length of the Additional Authenticated Data (AAD) in bytes
#define GCM_MAX_TAGLEN AES_BLOCKLEN

struct AES_GCM_ctx {
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t* Iv;
  size_t IvLen;
};

void AES_GCM_init_ctx(struct AES_GCM_ctx* ctx, const uint8_t* key);
int AES_GCM_set_iv(struct AES_GCM_ctx* ctx, const uint8_t* iv, size_t iv_len);
void AES_GCM_free_ctx(struct AES_GCM_ctx* ctx);


// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// In addition with GCM, an authentication tag is generated and verified to ensure integrity and authenticity of the data.
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 

struct AES_GCM_result {
  uint8_t* buf;
  // The caller owns this buffer and must allocate at least tag_length bytes.
  uint8_t* tag;
};


// Flag to simulate a side-channel attack. If set to 1, the AES_GCM_authenticated_encrypt_buffer function will store the result of the first application of the 
// S-box to the Xor of the key and the IV in the target_bytes buffer, and the hamming weight of each byte of the target_bytes in the hamming_weight buffer.
// This can be used to simulate a side-channel attack on the AES implementation.
#ifndef SIMULATE_ATTACK
  #define SIMULATE_ATTACK 1
#endif

// If it is desired to simulate a side-channel attack, the caller must allocate at least 16 bytes for this buffer, and set the SIMULATEATTACK macro to 1.
#if defined(SIMULATE_ATTACK) && (SIMULATE_ATTACK == 1)

  struct AES_GCM_attack_result {
    // target_bytes will store the result of the first application of the S-box to the Xor of the first 16 bytes of the key and the IV
    uint8_t target_bytes_p1[16];

    // hamming_weight will store the hamming weight of each byte of the target_bytes (first half of the key and the IV)
    uint8_t hamming_weight_p1[16];

    // target_bytes will store the result of the first application of the S-box to the Xor of the second 16 bytes of the key and the IV
    uint8_t target_bytes_p2[16];

    // hamming_weight will store the hamming weight of each byte of the target_bytes (second half of the key and the IV)
    uint8_t hamming_weight_p2[16];
  };

  struct AES_GCM_attack_result* get_attack_result(void);

  void restart_attack_simulation(void);

  void set_attack_simulation(int enable);

#endif


void AES_GCM_authenticated_encrypt_buffer(struct AES_GCM_ctx* ctx, struct AES_GCM_result* res, size_t length, uint8_t* aad, size_t aad_length, size_t tag_length);

int AES_GCM_authenticated_decrypt_buffer(struct AES_GCM_ctx* ctx, struct AES_GCM_result* res, size_t length, const uint8_t* tag, size_t tag_length, uint8_t* aad, size_t aad_length);

#endif // #if defined(GCM) && (GCM == 1)


#endif // _AES_H_
