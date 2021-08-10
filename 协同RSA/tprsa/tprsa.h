#ifndef TPRSA_TPRSA_H
#define TPRSA_TPRSA_H

#include <openssl/opensslconf.h>
#include <openssl/bn.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#ifndef OPENSSL_NO_TPRSA

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned short prime_t;

static const prime_t primes_1024_bits[75] = {
         4,     3,     5,     7,    11,    13,    17,    19,
        23,    29,    31,    37,    41,    43,    47,    53,
        59,    61,    67,    71,    73,    79,    83,    89,
        97,   101,   103,   107,   109,   113,   127,   131,
        137,   139,   149,   151,   157,   163,   167,   173,
        179,   181,   191,   193,   197,   199,   211,   223,
        227,   229,   233,   239,   241,   251,   257,   263,
        269,   271,   277,   281,   283,   293,   307,   311,
        313,   317,   331,   337,   347,   349,   353,   457,
        479,   509,   661
};

static const prime_t primes_2048_bits[131] = {
         4,     3,     5,     7,    11,    13,    17,    19,
        23,    29,    31,    37,    41,    43,    47,    53,
        59,    61,    67,    71,    73,    79,    83,    89,
        97,   101,   103,   107,   109,   113,   127,   131,
        137,   139,   149,   151,   157,   163,   167,   173,
        179,   181,   191,   193,   197,   199,   211,   223,
        227,   229,   233,   239,   241,   251,   257,   263,
        269,   271,   277,   281,   283,   293,   307,   311,
        313,   317,   331,   337,   347,   349,   353,   359,
        367,   373,   379,   383,   389,   397,   401,   409,
        419,   421,   431,   433,   439,   443,   449,   457,
        461,   463,   467,   479,   487,   491,   499,   503,
        509,   521,   523,   541,   547,   557,   563,   569,
        571,   577,   587,   593,   599,   601,   607,   613,
        617,   619,   631,   641,   643,   647,   653,   659,
        661,   673,   677,   683,   691,   701,   709,   751,
        1069,   1201,   5867
};

static const prime_t primes_4096_bits[233] = {
        4,      3,     5,     7,    11,    13,    17,    19,
        23,    29,    31,    37,    41,    43,    47,    53,
        59,    61,    67,    71,    73,    79,    83,    89,
        97,   101,   103,   107,   109,   113,   127,   131,
        137,   139,   149,   151,   157,   163,   167,   173,
        179,   181,   191,   193,   197,   199,   211,   223,
        227,   229,   233,   239,   241,   251,   257,   263,
        269,   271,   277,   281,   283,   293,   307,   311,
        313,   317,   331,   337,   347,   349,   353,   359,
        367,   373,   379,   383,   389,   397,   401,   409,
        419,   421,   431,   433,   439,   443,   449,   457,
        461,   463,   467,   479,   487,   491,   499,   503,
        509,   521,   523,   541,   547,   557,   563,   569,
        571,   577,   587,   593,   599,   601,   607,   613,
        617,   619,   631,   641,   643,   647,   653,   659,
        661,   673,   677,   683,   691,   701,   709,   719,
        727,   733,   739,   743,   751,   757,   761,   769,
        773,   787,   797,   809,   811,   821,   823,   827,
        829,   839,   853,   857,   859,   863,   877,   881,
        883,   887,   907,   911,   919,   929,   937,   941,
        947,   953,   967,   971,   977,   983,   991,   997,
        1009,  1013,  1019,  1021,  1031,  1033,  1039,  1049,
        1051,  1061,  1063,  1069,  1087,  1091,  1093,  1097,
        1103,  1109,  1117,  1123,  1129,  1151,  1153,  1163,
        1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223,
        1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,
        1289,  1291,  1297,  1301,  1303,  1307,  1319,  1321,
        1327,  1361,  1367,  1373,  1381,  1399,  1409,  1423,
        1427,  1429,  1433,  1439,  1447,  1451,  1721,  2011,
        2203  
};

const prime_t *PRIMES_ARRAY;
int LEN_OF_ARRAY;
int PRIMES_BITS;
int LEN_OF_PRE;

struct TPRSA_Paillier
{   
    BIGNUM* g;
    BIGNUM* N;
    BIGNUM* N_2;
    BIGNUM* lambda;
    BIGNUM* mu;
};

    /*****************************************************************************************/
    /*                          struct for TPRSA client and server                           */
    /*****************************************************************************************/

    typedef RSA TPRSA_KEY;                                  /*TPRSA key struct*/
    typedef struct TPRSA_Paillier TPRSA_PAILLIER;           /*TPRSA paillier key struct*/
    typedef struct TPRSA_client TPRSA_CLIENT;               /*TPRSA signature client struct*/
    typedef struct TPRSA_server TPRSA_SERVER;               /*TPRSA signature server struct*/
    typedef struct TPRSA_Paillier_pk TPRSA_PAILLIER_PK;     /*TPRSA paillier pk key struct*/
    typedef struct TPRSA_Paillier_sk TPRSA_PAILLIER_SK;     /*TPRSA paillier sk key struct*/
    typedef struct TPRSA_dealer TPRSA_DEALER;               /*TPRSA trusted third party*/
    typedef struct TPRSA_sk TPRSA_SK;                       /*TPRSA Non-interactive sk struct*/

    
    /*****************************************************************************************/
    /*                                   TPRSA common method                                 */
    /*****************************************************************************************/

    /** Creates a new TPRSA_KEY object.
     * \return TPRSA_KEY object or NULL if an error occurred.
     */
    TPRSA_KEY* TPRSAK_new(void);

    /** Frees a TPRSA_KEY object.
     * \param key TPRSA_KEY object to be freed.
     */
    void TPRSAK_Free(TPRSA_KEY* key);

    /** Generates a pair {n, e, d} in TPRSA_KEY object.
     * \param key TPRSA_KEY object.
     * \return 1 on success and 0 if an error occurred.
     */
    int TPRSA_key_gen(TPRSA_KEY *key);

    /*inside for TPRSA Paillier*/
    int TPRSA_Paillier_L(BIGNUM* ans, const BIGNUM*a, const BIGNUM* b, const BIGNUM* c, const BIGNUM* d);

    /** Generate a pair pkP {g,N,N_2} and skP {lambda, mu, N, N_2} for TPCq、TPCp
     * \param key TPRSA_PAILLIER object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_Paillier_Generate_Key(TPRSA_PAILLIER* key);

    /** Generate a pair pkP {g,N,N_2} and skP {lambda, mu, N,N_2} for TPCD
     * \param key TPRSA_PAILLIER object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_Paillier_Generate_Key2(TPRSA_PAILLIER* key);

    /** Generate the ciphertext by Paillier key
     * \param message plantext
     * \param ciphertext result of the encrypt
     * \param key TPRSA_PAILLIER object
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_Paillier_Enc_Message(const BIGNUM* message, BIGNUM* ciphertext, const TPRSA_PAILLIER* key);

    /** Decrypt the ciphertext
     * \param Dec_ciphertext result of function
     * \param ciphertext need to decrypt ciphertext
     * \param key TPRSA_PAILLIER object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_Paillier_Dec_Ciphertext(BIGNUM* Dec_ciphertext, const BIGNUM* ciphertext, const TPRSA_PAILLIER* key);

    /** Generate message SHA1 digest
     * \param flen from bytes
     * \param from message
     * \param digest result
     * \param tlen digest len
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_Generate_SHA1(int flen, const unsigned char* from, unsigned char* digest, int tlen);

    /** Generate message SHA256 digest
     * \param flen from bytes
     * \param from message
     * \param digest result
     * \param tlen digest len
     */
    int TPRSA_Generate_SHA256(int flen, const unsigned char* from, unsigned char* digest, int tlen);

    /** Generate TPRSA ciphertext
     * \param flen bytes of from
     * \param from message
     * \param to result of encrypt
     * \param rsa key
     * \param padding pkcs#1 type
     */
    int TPRSA_private_encrypt(int flen, const unsigned char* from, unsigned char* to, TPRSA_KEY* rsa, int padding);

    /** Decrypt from by private with no padding
     * \param flen bytes of from
     * \param from message
     * \param rsa key
     * \param ret BIGNUM result
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_private_decrypt_NO_PADDING(int flen, const unsigned char *from, TPRSA_KEY *rsa, BIGNUM *ret);

    /** Decrypt message with padding
     * \param to decrypt result
     * \param sbignum server decrypt with no padding result
     * \param cbignum client decrypt with no padding result
     * \param tprsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_private_finally_decrypt(unsigned char* to, const BIGNUM* sbignum, const BIGNUM* cbignum, TPRSA_KEY* tprsa, int padding);

    /** Generate TPRSA sign
     * \param type NID_sha1 or NID_sha256
     * \param m digest of message
     * \param m_len len of digest
     * \param sigret result of sign
     * \param siglen len of sigret
     * \param rsa key
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, TPRSA_KEY *rsa);

    /** Generate a collaborate sign 
     * \param client_sign sign from client
     * \param client_sign_len client sign len
     * \param server_sign sign from server
     * \param server_sign_len server sign len
     * \param sigret collaborate sign ptr
     * \param tprsa TPRSA_KEY object
     * \return sigret len or -1 if an error occurred.
     */
    int TPRSA_Collaborate_Sign(const unsigned char *client_sign, const unsigned int client_sign_len, 
                            const unsigned char *server_sign, const unsigned int server_sign_len, 
                            unsigned char *sigret, TPRSA_KEY* tprsa);

    /** RSA signature verify for tprsa
     * \param dtype message digest type,NID_sha1 or NID_sha256
     * \param m message digest
     * \param m_len len of message
     * \param sigbuf signature buffer
     * \param tprsa TPRSA_KEY obeject.
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, TPRSA_KEY *tprsa);

    /** 4098 public decrypt
     * \param flen len of from
     * \param from ciphertext need to decrypt
     * \param to decrypt result
     * \param tprsa TPRSA_KEY obeject
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occured.
     */ 
    int TPRSA_4096_public_decrypt(int flen, const unsigned char *from, 
                              unsigned char *to, TPRSA_KEY *tprsa, int padding);

    /** 4096 public encrypt
     * \param flen len of from
     * \param to encrypt result
     * \param tprsa TPRSA_KEY object
     * \param padding padding type
     * \return 1 on success or 0 if an error occrued.
     */
    int TPRSA_4096_public_encrypt(int flen, const unsigned char *from, 
                                unsigned char *to, TPRSA_KEY *tprsa, int padding);

    /*inside in TPRSA_4096_verify*/
    int int_TPRSA_4096_verify(int dtype, const unsigned char *m,
                   unsigned int m_len,
                   unsigned char *rm, size_t *prm_len,
                   const unsigned char *sigbuf, size_t siglen, TPRSA_KEY *tprsa);

    /*inside in TPRSA_4096_verify*/
    int rsa_check_digestinfo(X509_SIG *sig, const unsigned char *dinfo,
                                int dinfolen);

    /*****************************************************************************************/
    /*                                   TPRSA client method                                 */
    /*****************************************************************************************/
    
    /** Client Precompiled
     * \param r TPRSA_CLIENT object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Precompiled(TPRSA_CLIENT *r);

    /* inside TPRSA_CLIENT_PRECOMPILED */
    int TPRSA_CLIENT_Set_Continuous_Primes(TPRSA_CLIENT* r);

    /* inside TPRSA_CLIENT_PRECOMPILED */
    int TPRSA_CLIENT_Set_CRT(TPRSA_CLIENT *r);
    
    /* inside TPRSA_CLIENT_PRECOMPILED */
    int TPRSA_CLIENT_Set_t_phi(TPRSA_CLIENT* r);

    /* inside TPRSA_CLIENT_PRECOMPILED */
    int TPRSA_CLIENT_Set_Primes_Array(TPRSA_CLIENT* r);

    /** Creates a new TPRSA_CLIENT object
     * \param key TPRSA_KEY object
     * \param type public key bits, 1024, 2048, 4096
     * \return TPRSA_CLIENT object or NULL if an error occurred.
     */
    TPRSA_CLIENT* TPRSA_CLIENT_new(TPRSA_KEY* key, int type);

    /** Frees TPRSA_CLIENT object.
     * \param r TPRSA_CLENT object
     */
    void TPRSA_CLIENT_Free(TPRSA_CLIENT* r);

    /** Set pa
     * \param r TPRSA_CLIENT object
     * \param i primes num
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Set_pa(TPRSA_CLIENT *r, int i);

    /** Set qa
     * \param r TPRSA_CLIENT object
     * \param i primes num
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Set_qa(TPRSA_CLIENT *r, int i);

    /** Set pkp
     * \param r TPRSA_CLIENT object
     * \param k pkP key
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Set_pkP(TPRSA_CLIENT* r, TPRSA_PAILLIER* k);

    /** Set n
     * \param r TPRSA_CLIENT object
     * \param n RSA mod n
     */
    int TPRSA_CLIENT_Set_n(TPRSA_CLIENT*r, const BIGNUM* n);

    /** Set e
     * \param r TPRSA_CLIENT object
     */
    int TPRSA_CLIENT_Set_e(TPRSA_CLIENT*r);

    /** Set TPRSA pk e
     * \param r TPRSA_CLIENT object
     * \param e TPRSA pk e
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Set0_e(TPRSA_CLIENT*r, const BIGNUM* e);

    /** Set Client da
     * \param r TPRSA_CLIENT object
     * \param da private pieces key
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Set_da(TPRSA_CLIENT* r, const BIGNUM* da);

    /** Genetate ciphertext by pkP
     * \param r TPRSA_CLIENT object
     * \param ret ciphertext BIGNUM result
     * \param m plantext
     * \return ciphertext or NULL if an error occurred.
     */
    BIGNUM* TPRSA_CLIENT_pkP_Enc(TPRSA_CLIENT* r, BIGNUM* ret, const BIGNUM* m);

    /** Get ta
     * \param r TPRSA_CLIENT object
     * \return ta or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_CLIENT_get_ta(TPRSA_CLIENT* r);

    /** Get phi_ta
     * \param r TPRSA_CLIENT object
     * \return phi_ta or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_CLIENT_get_phi_ta(TPRSA_CLIENT *r);

    /** Get pa
     * \param r TPRSA_CLIENT object
     * \return pa or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_CLIENT_get_pa(TPRSA_CLIENT *r);

    /** Get qa
     * \param r TPRSA_CLIENT object
     * \return qa or NULL if an error occured.
     */
    const BIGNUM* TPRSA_CLIENT_get_qa(TPRSA_CLIENT *r);

    /** Get N_2
     * \param r TPRSA_CLIENT object
     * \return N_2 or NULL if an error occured.
     */
    const BIGNUM* TPRSA_CLIENT_get_N_2(TPRSA_CLIENT *r);

    /** Get n
     * \param r TPRSA_CLIENT object
     * \return n TPRSA mod n.
     */
    const BIGNUM* TPRSA_CLIENT_get_n(TPRSA_CLIENT* r);

    /*inside TPRSA CLIENT Function*/
    const BIGNUM* TPRSA_CLIENT_get_random_range(const BIGNUM* e);

    /*inside TPRSA CLIENT Function*/
    const BIGNUM* TPRSA_CLIENT_get_random_(int bits);

    /** Get e_phi_na
     * \param r TPRSA_CLIENT object
     * \return e_phi_na BIGNUM object
     */
    const BIGNUM* TPRSA_CLIENT_get_EPHINA(TPRSA_CLIENT* r);

    /** Get TPRSA pk e
     * \param r TPRSA_CLIENT object
     * \return RSA PK BIGNUM e or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_CLIENT_get_e(TPRSA_CLIENT* r);

    /** Get da
     * \param r TPRSA_CLIENT object
     * \return da or NULL if an error occured.
     */
    const BIGNUM* TPRSA_CLIENT_get_da(TPRSA_CLIENT* r);

    /** Check p is primes
     * \param r TPRSA_CLIENT object
     * \param a primes pa
     * \param b primes ps
     * \param tp mod
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Check_pv(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* tp);

    /** Check q is primes
     * \param r TPRSA_CLIENT object
     * \param a primes qa
     * \param b primes qs
     * \param tq mod
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_Check_qv(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* tq);

    /** Compute ctp
     * \param r TPRSA_CLIENT object
     * \param ctp BIGNUM object
     * \param cts BIGNUM object
     * \param ctps BIGNUM object
     * \return BIGNUM result or NULL if an error occurred.
     */
    int TPRSA_CLIENT_COMPUTE_CTP(TPRSA_CLIENT* r, BIGNUM *ctp, const BIGNUM* cts, const BIGNUM* ctps);

    /** Compute ctq
     * \param r TPRSA_CLIENT object
     * \param ctq BIGNUM object
     * \param cts BIGNUM object
     * \param ctps BIGNUM object
     * \return BIGNUM result or NULL if an error occured.
     */
    int TPRSA_CLIENT_COMPUTE_CTQ(TPRSA_CLIENT* r, BIGNUM* ctq, const BIGNUM* cts, const BIGNUM* ctps);

    /** Get pkP
     * \param r TPRSA_CLIENT object
     */
    const TPRSA_PAILLIER* TPRSA_CLIENT_get_pkP(TPRSA_CLIENT* r);

    /*inside TPRSA_CLIENT_COM_Cn*/
    const BIGNUM* TPRSA_CLIENT_pkP_Enc_MULT_TWO(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b);

    /** Compute cn
     * \param r TPRSA_CLIENT object
     * \param cn BIGNUM result
     * \param cp encrypt ps from server
     * \param cq encrypt qs from server
     * \return cn
     */
    const BIGNUM* TPRSA_CLIENT_COM_Cn(TPRSA_CLIENT* r, BIGNUM* cn,const BIGNUM* cp, const BIGNUM* cq);

    /** Compute e_phi_na
     * \param r TPRSA_CLIENT object
     */
    int TPRSA_CLIENT_COM_EPHINA(TPRSA_CLIENT* r);

    /** Compute c_m_phi_n
     * \param r TPRSA_CLIENT object
     * \param ret BIGNUM object
     * \param c_phi_ns BIGNUM object
     * \return 1 on succees and 0 an error occurred.
     */
    int TPRSA_CLIENT_COM_C_MPHIN(TPRSA_CLIENT* r, BIGNUM* ret, const BIGNUM* c_phi_ns);

    /** Com cr3
     * \param r TPRSA_CLIENT object
     * \param cr3 BIGNUM object
     * \param c_eta_s BIGNUM object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_COM_cr3(TPRSA_CLIENT* r, BIGNUM* cr3, const BIGNUM* c_eta_s);

    /** Compute cs
     * \param r TPRSA_CLIENT object
     * \param cs result or NULL if an error occured
     * \param c_rho_s from server
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_CLIENT_COM_cs(TPRSA_CLIENT* r, BIGNUM* cs, const BIGNUM* c_rho_s);

    /** Encrypt message in client e
     * \param flen from len
     * \param to ptr point ciphertext
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_public_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** Encrypt message in client da
     * \param flen from len
     * \param to ptr point ciphertext
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_CLIENT_private_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** decrypt message in client e
     * \param flen from len
     * \param to ptr point ciphertext
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_CLIENT_public_decrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** encrypt message in client ds
     * \param flen from len
     * \param to ciphertext or NULL if an error occured
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_CLIENT_private_decrypt(int flen, const unsigned char *from, TPRSA_KEY* rsa, BIGNUM* ret);

    /** Get rsa key
     * \param r TPRSA_CLIENT object
     * \return key or NULL if an error occurred.
     */
    const TPRSA_KEY* TPRSA_CLIENT_get_rsa_key(TPRSA_CLIENT* r);



    /*****************************************************************************************/
    /*                                   TPRSA server method                                 */
    /*****************************************************************************************/
    
    /** TPRSA Server Precomiled
     * \param r TPRSA_SERVER obeject
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_Precompiled(TPRSA_SERVER *r);

    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_Continuous_Primes(TPRSA_SERVER* r);

    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_CRT(TPRSA_SERVER *r);

    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_Paillier_key(TPRSA_SERVER* r);

    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_Paillier_key2(TPRSA_SERVER* r);
    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_t_phi(TPRSA_SERVER* r);

    /*inside in TPRSA_SERVER_PRECOMPILED*/
    int TPRSA_SERVER_Set_Primes_Array(TPRSA_SERVER* r);

    /** Creates a new TPRSA_SERVER object
     * \param key TPRSA_KEY object
     * \param type TPRSA public key len,1024、2048、4096
     * \return TPRSA_SERVER object
     */
    TPRSA_SERVER* TPRSA_SERVER_new(TPRSA_KEY* key, int type);

    /** Frees TPRSA_SERVER object.
     * \param r TPRSA_SERVER object.
     */
    void TPRSA_SERVER_Free(TPRSA_SERVER* r);


    /** Set ps
     * \param r TPRSA_SERVER object
     * \param i nums of primes
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_Set_ps(TPRSA_SERVER *r,int i);

    /** Set qs
     * \param r TPRSA_SERVER object
     * \param i nums of primes
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_Set_qs(TPRSA_SERVER *r, int i);

    /** Get e
     * \param r TPRSA_SERVER object
     * \param e TPRSA pk e
     * \return 1 on success of 0 if an error occurred.
     */
    int TPRSA_SERVER_Set_e(TPRSA_SERVER* r, const BIGNUM* e);

    /** Set n
     * \param r TPRSA_SERVER object
     * \param n TPRSA public key
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_SERVER_Set_n(TPRSA_SERVER*r, const BIGNUM* n);

    /** Set sk piece ds
     * \param r TPRSA_SERVER object
     * \param ds sk piece
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_Set_ds(TPRSA_SERVER*r, const BIGNUM* ds);

    /** Get ds
     * \param r TPRSA_SERVER object
     * \return ds or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_ds(TPRSA_SERVER* r);

    /** Get ts
     * \param r TPRSA_SERVER object
     * \return ts or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_ts(TPRSA_SERVER* r);

    /** Get phi_ts
     * \param r TPRSA_SERVER object
     * \return phi_ts or NULL if an error occured.
     */
    const BIGNUM* TPRSA_SERVER_get_phi_ts(TPRSA_SERVER *r);

    /** Get Paillier pkP
     * \param r TPRSA_SERVER object
     * \return pkP or NULL if an error occurred.
     */
    TPRSA_PAILLIER* TPRSA_SERVER_get_pkP(TPRSA_SERVER* r);

    /*inside TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_PS*/
    const BIGNUM* TPRSA_SERVER_get_random(int bits);

    /** Get qs
     * \param r TPRSA_SERVER object
     * \return qs or NULL if an error occured.
     */
    const BIGNUM* TPRSA_SERVER_get_qs(TPRSA_SERVER *r);

    /** Get ps
     * \param r TPRSA_SERVER object
     * \return ps or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_ps(TPRSA_SERVER *r);

    /** Get e_phi_s
     * \param r TPRSA_SERVER object
     * \return e_phi_s or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_e_phi_s(TPRSA_SERVER* r);

    /** Get e_phi_ps
     * \param r TPRSA_SERVER object
     * \return e_phi_ps or NULL if an error occured.
     */
    const BIGNUM* TPRSA_SERVER_get_e_phi_ps(TPRSA_SERVER* r);

    /** Get n 
     * \param r TPRSA_SERVER object
     * \return n or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_n(TPRSA_SERVER* r);

    /** Get e_phi_ns
     * \param TPRSA_SERVER object
     * return e_phi_ns or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_EPHINS(TPRSA_SERVER* r);

    /** Genetate ciphertext by pkP
     * \param r TPRSA_SERVER object
     * \param ret BIGNUM object
     * \param m BIGNUM object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_pkP_Enc(TPRSA_SERVER* r, BIGNUM* ret, const BIGNUM* m);

    /** Decrypt ciphertext by skP
     * \param r TPRSA_SERVER object
     * \param ret plantext BIGNUM result
     * \param m ciphertext
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_SERVER_skP_Dec(TPRSA_SERVER* r, BIGNUM* ret ,const BIGNUM* c);


    /** Compute e_phi_s, e_phi_ps
     * \param r TPRSA_SERVER object
     * \param tp mod 
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_PS(TPRSA_SERVER* r, const BIGNUM* tp);

    /** Compute e_phi_s, e_phi_qs
     * \param r TPRSA_SERVER object
     * \param tp mod
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_QS(TPRSA_SERVER* r, const BIGNUM* tp);

    /** Decrypt com cn
     * \param r TPRSA_SERVER object
     * \param cn BIGNUM from client
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_SERVER_DEC_COM_n(TPRSA_SERVER* r, const BIGNUM* cn); 

    /** Com e_phi_ns
     * \param r TPRSA_SERVER object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_COM_EPHINS(TPRSA_SERVER* r);

    /** Get e
     * \param r TPRSA_SERVER object
     * \return e or NULL if an error occurred.
     */
    const BIGNUM* TPRSA_SERVER_get_e(TPRSA_SERVER* r);

    /** Com c_eta_s
     * \param r TPRSA_SERVER object
     * \param cm_phi_n from client
     * \return c_eta_s or NULL if an error occurred.
     */
    int TPRSA_SERVER_COM_CETAS(TPRSA_SERVER* r, BIGNUM *c_eta_s, const BIGNUM* cm_phi_n);

    /** Com c_rho_s
     * \param r TPRSA_SERVER object
     * \param c_rho_s BIGNUM or NULL if an error occured.
     * \param cr3 from clien
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_COM_c_rho_s(TPRSA_SERVER* r, BIGNUM* c_rho_s, const BIGNUM* cr3);

    /** Com ds
     * \param r TPRSA_SERVER object
     * \param cs from client
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_COM_ds(TPRSA_SERVER* r, const BIGNUM* cs);

    /** Encrypt message in SERVER e
     * \param flen from len
     * \param to ciphertext or NULL if an error occured
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_public_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** Encrypt message in SERVER da
     * \param flen from len
     * \param to ciphertext or NULL if an error occured
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_private_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** decrypt message in server e
     * \param flen from len
     * \param to ciphertext or NULL if an error occured
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_SERVER_public_decrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding);

    /** encrypt message in server ds
     * \param flen from len
     * \param to ciphertext or NULL if an error occured
     * \param rsa TPRSA_KEY object
     * \param padding pkcs#1 type
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SERVER_private_decrypt(int flen, const unsigned char *from, TPRSA_KEY* rsa, BIGNUM* ret);

    /** Get rsa key
     * \param r TPRSA_CLIENT object
     * \return key or NULL if an error occurred.
     */
    const TPRSA_KEY* TPRSA_SERVER_get_rsa_key(TPRSA_SERVER* r);


    /*****************************************************************************************/
    /*                                   TPRSA dealer method                                 */
    /*****************************************************************************************/

    /** Creates a new TPRSA_DEALER object.
     * \return TPRSA_DEALER object or NULL if an error occurred.
     */ 
    TPRSA_DEALER* TPRSA_DEALER_new(TPRSA_KEY* key);

    /** Frees a TPRSA_DEALER object.
     * \param d TPRSA_DEALER object to be freed.
     */
    void TPRSA_DEALER_Free(TPRSA_DEALER* d);

    /** Split to get the key piece
     * \param r TPRSA_DEALER object
     * \return 1 on success or 0 if an error occured.
     */
    int TPRSA_DEALER_TPSK(TPRSA_DEALER* r);

    /** Generate TPRSA a pair key (n, e, d)
     * \param d TPRSA_DEALER object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_DEALER_Gen_Key(TPRSA_DEALER* d);


    /*****************************************************************************************/
    /*                                   update 2020.9.24                                    */
    /*****************************************************************************************/

    /*****************************************************************************************/
    /*                             tprsa Non-interactive sk method                           */
    /*****************************************************************************************/

    /** Creates a new TPRSA_SK object
     * \param key TPRSA_KEY object
     * \return TPRSA_SK object or NULL if an error occurred.
     */
    TPRSA_SK *TPRSASK_new(TPRSA_KEY *key);

    /** Free a TPRSA_SK object.
     * \param sk TPRSA_SK obeject to be freed.
     */
    void TPRSASK_free(TPRSA_SK *sk);

    /** Generate a pair{n,e,ds,da} in TPRSA_SK object.
     * \param sk TPRSA_SK object
     * \param type TPRSA public len,1024,2048,4096
     * \param na TPRSA public key
     * \param ea TPRSA public key
     * \param eds TPRSA server sk
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Gen_Key_Eds(TPRSA_SK *sk, int type, BIGNUM *na, BIGNUM *ea, BIGNUM *eds);

    /** Generate a pair{n,e,ds,da} in TPRSA_SK object.
     * \param sk TPRSA_SK object
     * \param type TPRSA public len,1024,2048,4096
     * \param na TPRSA public key
     * \param ea TPRSA public key
     * \param ds TPRSA server sk
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Gen_Key_ds(TPRSA_SK *sk, int type, BIGNUM *na, BIGNUM *ea, BIGNUM *ds);

    /** Generates a Server RSA key
     * \param sk TPRSA_SK object
     * \param type 1024、2048、4096
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Gen_RSA(TPRSA_SK *sk, int type);

    /** Decrypto m to ret
     * \param sk TPRSA_SK object
     * \param ret BIGNUM
     * \param m BIGNUM
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_RSA_Dec(TPRSA_SK *sk, BIGNUM *ret, const BIGNUM *m);

    /** Get Server RSApk
     * \param sk TPRSA_SK object
     * \param Skey TPRSA_KEY object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Get_RSAPK(TPRSA_SK *sk, TPRSA_KEY *Skey);

    /** Set RSAPK
     * \param sk TPRSA_SK object
     * \param key TPRSA_KEY object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Set_RSAPK(TPRSA_SK *sk, TPRSA_KEY *Skey);

    /** Gets n from TPRSA_SK object
     * \param sk TPRSA_SK object
     * \param n TPRSA public key
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Get_n(TPRSA_SK *sk, BIGNUM *n);

    /** Gets e from TPRSA_SK object
     * \param sk TPRSA_SK object
     * \param e TPRSA public key
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Get_e(TPRSA_SK *sk, BIGNUM *e);

    /** Gets d from TPRSA_SK object
     * \param sk TPRSA_SK object
     * \param d TPRSA a piece private key object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Get_d(TPRSA_SK *sk, BIGNUM *d);

    /** Set n into sk
     * \param sk TPRSA_SK object
     * \param n BIGNUM object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Set_n(TPRSA_SK *sk, const BIGNUM *n);

    /** Set e into sk
     * \param sk TPRSA_SK object
     * \param e BIGNUM object
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Set_e(TPRSA_SK *sk, const BIGNUM *e);

    /** Set d into sk
     * \param sk TPRSA_SK object
     * \param d a piece private key
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_Set_d(TPRSA_SK *sk, const BIGNUM *d);

    /** Divide Client sk
     * \param sk TPRSA_SK object
     * \param na client's public key n
     * \param ea client's public key e
     * \param ds server's private key 
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_DivKey_ds(TPRSA_SK *sk, BIGNUM *na, BIGNUM *ea, BIGNUM *ds);

    /** Divide Client sk
     * \param sk TPRSA_SK object
     * \param na client's public key n
     * \param ea client's public key e
     * \param eds server's private key 
     * \return 1 on success or 0 if an error occurred.
     */
    int TPRSA_SK_DivKey_Eds(TPRSA_SK *sk, BIGNUM *na, BIGNUM *ea, BIGNUM *eds);
#ifdef __cplusplus
}
#endif


#ifndef OPENSSL_NO_ERR
#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/err.h>
#define TPRSAerr(f,r)  ERR_PUT_error(ERR_LIB_RSA,(f),(r),__FILE__,__LINE__)

#define ERR_LIB_TPRSA   83

#define TPRSA_F_TPRSA_PRIVATE_ENCRYPT               120
#define TPRSA_F_TPRSA_PRIVATE_DECRYPT               122
#define TPRSA_F_TPRSA_GENERATE_SHA1                 123
#define TPRSA_F_TPRSA_PRIVATE_FINALLY_DECRYPT       124
#define TPRSA_F_TPRSA_PAILLIER_L                    125
#define TPRSA_F_TPRSA_GENERATE_CONTINUOUS_PRIMES    126
#define TPRSA_F_TPRSA_PAILLIER_KEY_GENERATE         127
#define TPRSA_F_TPRSA_PAILLIER_ENC_MESSAGE          128
#define TPRSA_F_TPRSA_PAILLIER_DEC_CIPHERTEXT       129
#define TPRSA_F_TPRSA_CLIENT_NEW                    130
#define TPRSA_F_TPRSA_CLIENT_SET_T_PHI              131
#define TPRSA_F_TPRSA_CLIENT_SET_PRIMES_ARRAY       132
#define TPRSA_F_TPRSA_CLIENT_SET_PKP                133
#define TPRSA_F_TPRSA_CLIENT_SET_PA                 134
#define TPRSA_F_TPRSA_CLIENT_SET_QA                 135
#define TPRSA_F_TPRSA_CLIENT_CHECK_V                136
#define TPRSA_F_TPRSA_CLIENT_COMPUTER_CTP           137
#define TPRSA_F_TPRSA_CLIENT_COMPUTER_CTQ           138
#define TPRSA_F_TPRSA_CLIENT_PKP_ENC_MULT_TWO       139
#define TPRSA_F_TPRSA_CLIENT_COM_CN                 140
#define TPRSA_F_TPRSA_CLIENT_SET_N                  141
#define TPRSA_F_TPRSA_CLIENT_SET_E                  142
#define TPRSA_F_TPRSA_CLIENT_GET_RANDOM             143
#define TPRSA_F_TPRSA_CLIENT_GET_RANDOM_RANGE       144
#define TPRSA_F_TPRSA_CLIENT_COM_EPHINA             145
#define TPRSA_F_TPRSA_CLIENT_COM_C_MPHIN            146
#define TPRSA_F_TPRSA_CLIENT_COM_CR3                147
#define TPRSA_F_TPRSA_CLIENT_COM_CS                 148
#define TPRSA_F_TPRSA_SERVER_SET_PAILLIER_KEY       149
#define TPRSA_F_TPRSA_SERVER_SET_T_PHI              150
#define TPRSA_F_TPRSA_SERVER_SET_PRIMES_ARRAY       151
#define TPRSA_F_TPRSA_SERVER_SET_PS                 152
#define TPRSA_F_TPRSA_SERVER_SET_QS                 153
#define TPRSA_F_TPRSA_SERVER_SET_PKP                154
#define TPRSA_F_TPRSA_SERVER_GET_RANDOM             155
#define TPRSA_F_TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_PS   156
#define TPRSA_F_TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_QS   157
#define TPRSA_F_TPRSA_SERVER_DEC_COM_N                  158
#define TPRSA_F_TPRSA_SERVER_COM_EPHINS                 159
#define TPRSA_F_TPRSA_SERVER_SET_E                      160
#define TPRSA_F_TPRSA_SERVER_COM_CETAS                  161
#define TPRSA_F_SERVER_COM_C_RHO_S                      162
#define TPRSA_F_TPRSA_SERVER_COM_DS                     163
#define TPRSA_F_TPRSA_KEY_GEN                           164
#define TPRSA_F_TPRSA_DEALER_TRSK                       165
#define TPRSA_F_TPRSA_DEALER_NEW                        166
#define TPRSA_F_TPRSA_SERVER_SET_DS                     167
#define TRRAS_F_TPRSA_SERVER_SET_N                      168
#define TPRSA_F_TPRSA_CLIENT_SET0_E                     169
#define TPRSA_F_TPRSA_COLLABORATE_SIGN                  170
#define TPRSA_F_TPRSA_PRE_CRT                           171
#define TPRSA_F_TPRSA_SERVER_NEW                        172
#define TPRSA_F_TPRSA_SERVER_PRECOMPILED                173
#define TPRSA_F_TPRSA_CLIENT_PRECOMPILED                174
#define TPRSA_F_TPRSA_CLIENT_SET_DA                     175


#define TPRSA_R_UNKNOW_PADDING_TYPE 120
#define TPRSA_R_PADDING_CHECK_FAILED 121
#define TPRSA_R_GENERATE_SHA1_FAILED 122
#define TPRSA_R_PARAMS_NULL_ERROR 123
#define TPRSA_R_PRECOMPILED_FAILED 124
#define TPRSA_R_UNKNOW_LEN_TYPE 125

#ifdef __cplusplus
}
#endif

#endif

#endif
#endif
