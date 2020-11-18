//#include <M5Stack.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <base64.h>
#include <string.h>

mbedtls_md_context_t ctx;
mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

mbedtls_pk_context PrivKey;

mbedtls_ecdsa_context ECDSA_Context;

unsigned char key[32];

char peers[] = "aka+fuka-siz98&bit$maj";
int ret;

extern "C" {
#include "crypto/base64.h"
}

//const char public_key[] = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==";

//const char private_key[] ="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";

const char PUBLIC_KEY[] =
"-----BEGIN EC PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n"
"q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n"
"-----END EC PUBLIC KEY-----\n";

const char PRIVATE_KEY[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
"OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
"1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
"-----END EC PRIVATE KEY-----\n";

void setup(){
    //M5.begin();
    //M5.Power.begin();

    Serial.begin(115200);
    Serial.println("Siz maj bit");

    //mbedtls_entropy_init( &entropy );

    mbedtls_ctr_drbg_init( &ctr_drbg );

    /*
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) peers, strlen( peers ) ) ) != 0 ){
        Serial.print("drbg init ret: ");
        Serial.print(ret);
        while(true){
            delay(100);
        }
    }
    */

    char header[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

    char payload[] = "{\"sub\":\"aabbccddeeff\",\"Exp\":1516239022,\"iat\":1516230022}";

    //char *payload = "Hello SHA 256!";
    byte shaResult[32];

    char payload64[300] = "siz";

    char header64[100];
    char pld64[100];
    sprintf(&header64[0], "%s", base64::encode(header).c_str());
    sprintf(&pld64[0], "%s", base64::encode(payload).c_str());

    strcpy(payload64, header64);
    strcat(payload64, ".");
    strcat(payload64, pld64);

    const size_t payloadLength = strlen(payload64);         

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *) payload64, payloadLength);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);

    mbedtls_pk_init(&PrivKey);

    mbedtls_pk_setup(&PrivKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

    /*
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, 
                                    mbedtls_pk_ec(PrivKey),
                                    mbedtls_ctr_drbg_random,
                                    &(ctr_drbg));
    */


    mbedtls_pk_parse_key(&PrivKey, (unsigned char*)PRIVATE_KEY, strlen(PRIVATE_KEY) + 1, NULL, 0);
    mbedtls_pk_parse_public_key(&PrivKey, (unsigned char*)PUBLIC_KEY, strlen(PUBLIC_KEY) + 1);

    mbedtls_ecdsa_from_keypair(&ECDSA_Context, mbedtls_pk_ec(PrivKey));

    //unsigned char PrivBuf[100];

    //mbedtls_pk_write_key_pem(&PrivKey, PrivBuf, 100);

    unsigned char signature[200];// "at least twice as large as the size of the curve used, plus 9"
    size_t signature_length;
    ret = mbedtls_ecdsa_write_signature(&ECDSA_Context, MBEDTLS_MD_SHA256, shaResult, 32,
                                    signature, &signature_length,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret == 0) {
        char sizmajbituzkurvafix[MBEDTLS_ECDSA_MAX_LEN];
        sprintf(&sizmajbituzkurvafix[0], "%s", signature);
        Serial.print("Signature raw: ");
        Serial.println((char*)signature);        
        Serial.print("Signature: ");
        Serial.println(base64::encode(sizmajbituzkurvafix).c_str());
        Serial.print("slen: ");
        Serial.print(signature_length);
    } else {
        Serial.print("signing error: ");
        Serial.print(ret);
    }
    
    Serial.print("Hash: ");
    
    for(int i= 0; i< sizeof(shaResult); i++){
        char str[3];

        sprintf(str, "%02x", (int)shaResult[i]);
        Serial.print(str);
    }

    Serial.println();
    Serial.println(payload64);
}

void loop(){
    delay(100);
}
