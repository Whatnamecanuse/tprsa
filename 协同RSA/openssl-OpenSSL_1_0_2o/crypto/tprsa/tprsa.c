#include <stdio.h>
#include <openssl/tprsa.h>
#include "cryptlib.h"

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36

TPRSA_KEY* TPRSAK_new(void){
    TPRSA_KEY* ret = RSA_new();
    return ret;
}

void TPRSAK_Free(TPRSA_KEY* key){
    RSA_free(((RSA*)key));
}

int TPRSA_key_gen(TPRSA_KEY* key){
    BN_CTX *ctx;
    BIGNUM* ret = NULL;
    BIGNUM* phi = NULL;
    int r = -1;

    if(!(ctx = BN_CTX_new()) || !(key->p = BN_new()) || !(key->q = BN_new()) || !(key->n = BN_new()) || !(key->e = BN_new()) || !(key->d = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_KEY_GEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    phi = BN_CTX_get(ctx);

    BN_generate_prime_ex(key->p, PRIMES_BITS, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(key->q, PRIMES_BITS, 0, NULL, NULL, NULL);

    BN_mul(key->n, key->q, key->p, ctx);

    BN_rand(key->e, PRIMES_BITS, -1, -1);
    while(BN_num_bits(key->e) == 0){
        BN_rand(key->e, PRIMES_BITS, -1, -1);
    }

    BN_one(phi);
    BN_one(ret);
    BN_sub(ret, key->p, phi);
    BN_sub(phi, key->q, phi);
    BN_mul(phi, phi, ret, ctx);

    BN_mod_inverse(key->d, key->e, phi, ctx);

    r = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return (r);
    }
}

int TPRSA_Paillier_L(BIGNUM*ans, const BIGNUM*a, const BIGNUM* b, const BIGNUM* c, const BIGNUM* d){
    BN_CTX* ctx;
    int r = 0;
    if( !ans || !a || !b || !c || !d){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_L, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_L, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    BN_mod_exp(ans, a, b, c, ctx);
    BN_sub_word(ans, 1);
    BN_div(ans, NULL, ans, d, ctx);
    r = 1;

 err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (r) ;  
    
}

int TPRSA_Paillier_Generate_Key(TPRSA_PAILLIER* key){
    BN_CTX *ctx;
    BIGNUM *Paillier_p1, *Paillier_p2, *Paillier_gcd, *Paillier_Eu, *Paillier_Temp;
    int r, k, bits;
    r = -1;
    k = 0;
    // bits = 2 * PRIMES_BITS + 512;
    bits = PRIMES_BITS/2 + 512;

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_KEY_GENERATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    Paillier_p1 = BN_CTX_get(ctx);
    Paillier_p2 = BN_CTX_get(ctx);
    Paillier_gcd = BN_CTX_get(ctx);
    Paillier_Eu = BN_CTX_get(ctx);
    Paillier_Temp = BN_CTX_get(ctx);

    while(BN_num_bits(Paillier_gcd) != 1){
        while(k == 0){
            k = rand() % bits;
        }
        BN_generate_prime_ex(Paillier_p1, bits, 0, NULL, NULL, NULL);
        
        k = 0;
        while(k == 0){
            k = rand() % bits;
        }

        BN_generate_prime_ex(Paillier_p2, bits, 0, NULL, NULL, NULL);

        BN_mul(key->N, Paillier_p1, Paillier_p2, ctx);
        BN_sub_word(Paillier_p1, 1);
        BN_sub_word(Paillier_p2, 1);
        BN_mul(Paillier_Eu, Paillier_p1, Paillier_p2, ctx);
        BN_gcd(Paillier_gcd, key->N, Paillier_Eu, ctx);

    }

    BN_one(Paillier_Temp);
    BN_add(key->g, key->N, Paillier_Temp);
    BN_gcd(Paillier_Temp, Paillier_p1, Paillier_p2, ctx);
    BN_div(key->lambda, NULL, Paillier_Eu, Paillier_Temp, ctx);

    BN_mul(key->N_2, key->N, key->N, ctx);

    r = TPRSA_Paillier_L(key->mu, key->g, key->lambda, key->N_2, key->N);
    BN_mod_inverse(key->mu, key->mu, key->N, ctx);


err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (r);
}

int TPRSA_Paillier_Generate_Key2(TPRSA_PAILLIER* key){
    BN_CTX *ctx;
    BIGNUM *Paillier_p1, *Paillier_p2, *Paillier_gcd, *Paillier_Eu, *Paillier_Temp;
    int r, k, bits;
    r = -1;
    k = 0;

    bits = PRIMES_BITS+256;

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_KEY_GENERATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    Paillier_p1 = BN_CTX_get(ctx);
    Paillier_p2 = BN_CTX_get(ctx);
    Paillier_gcd = BN_CTX_get(ctx);
    Paillier_Eu = BN_CTX_get(ctx);
    Paillier_Temp = BN_CTX_get(ctx);

    while(BN_num_bits(Paillier_gcd) != 1){
        while(k == 0){
            k = rand() % bits;
        }
        BN_generate_prime_ex(Paillier_p1, bits, 0, NULL, NULL, NULL);
        
        k = 0;
        while(k == 0){
            k = rand() % bits;
        }

        BN_generate_prime_ex(Paillier_p2, bits, 0, NULL, NULL, NULL);

        BN_mul(key->N, Paillier_p1, Paillier_p2, ctx);
        BN_sub_word(Paillier_p1, 1);
        BN_sub_word(Paillier_p2, 1);
        BN_mul(Paillier_Eu, Paillier_p1, Paillier_p2, ctx);
        BN_gcd(Paillier_gcd, key->N, Paillier_Eu, ctx);

    }

    BN_one(Paillier_Temp);
    BN_add(key->g, key->N, Paillier_Temp);
    BN_gcd(Paillier_Temp, Paillier_p1, Paillier_p2, ctx);
    BN_div(key->lambda, NULL, Paillier_Eu, Paillier_Temp, ctx);

    BN_mul(key->N_2, key->N, key->N, ctx);

    r = TPRSA_Paillier_L(key->mu, key->g, key->lambda, key->N_2, key->N);
    BN_mod_inverse(key->mu, key->mu, key->N, ctx);


err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (r);
}

int TPRSA_Paillier_Enc_Message(const BIGNUM* message, BIGNUM* ciphertext, const TPRSA_PAILLIER* key){
    int r = -1;
    BIGNUM *temp_g_exp_m, *temp_r_exp_N, *Paillier_r;
    if( BN_cmp(key->N, message) == (-1) ){
        printf("输入不正确\n");
        return 0;
    }
    BN_CTX* ctx;

    if( !message || !key){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_ENC_MESSAGE, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_ENC_MESSAGE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    temp_g_exp_m =  BN_CTX_get(ctx);
    temp_r_exp_N = BN_CTX_get(ctx);
    Paillier_r = BN_CTX_get(ctx);

    BN_rand_range(Paillier_r, key->N);
    while(BN_num_bits(Paillier_r) == 0){
        BN_rand_range(Paillier_r, key->N);
    }
    BN_mod_exp(temp_g_exp_m, key->g, message, key->N_2, ctx);
    BN_mod_exp(temp_r_exp_N,Paillier_r, key->N, key->N_2, ctx);
    BN_mod_mul(ciphertext, temp_g_exp_m, temp_r_exp_N, key->N_2, ctx);
    r = 1;


err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (r);
}

int TPRSA_Paillier_Dec_Ciphertext(BIGNUM* Dec_ciphertext, const BIGNUM* ciphertext, const TPRSA_PAILLIER* key){
    int r = -1;
    BN_CTX* ctx;

    if( !ciphertext || !key){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_DEC_CIPHERTEXT, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PAILLIER_DEC_CIPHERTEXT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    r = TPRSA_Paillier_L(Dec_ciphertext, ciphertext, key->lambda, key->N_2, key->N);
    BN_mod_mul(Dec_ciphertext, Dec_ciphertext, key->mu, key->N,ctx);
    

err:

    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }    
    return (r);
}

int TPRSA_private_encrypt(int flen, const unsigned char* from, unsigned char* to, TPRSA_KEY* rsa, int padding){
    
    BIGNUM *f, *ret, *res;
    int i, j, k, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char*)OPENSSL_malloc(num);
    if( !f || !ret || !buf ){
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
        break;
    case RSA_X931_PADDING:
        i = RSA_padding_add_X931(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    case RSA_SSLV23_PADDING:
    default:
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if(i < 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;
    
    if (BN_ucmp(f, rsa->n) >= 0){
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_ENCRYPT, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }

     if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
        if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
            goto err;
    } else {
        BIGNUM local_d;
        BIGNUM *d = NULL;

        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
            BN_init(&local_d);
            d = &local_d;
            BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
        } else
            d = rsa->d;

        if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
            if (!BN_MONT_CTX_set_locked
                (&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
                goto err;

        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n))
            goto err;
    }


    if(padding == RSA_X931_PADDING){
        BN_sub(f, rsa->n, ret);
        if (BN_cmp(ret, f) > 0)
            res = f;
        else
                res = ret;
    } else
        res = ret;

    j = BN_num_bytes(res);
    i = BN_bn2bin(res, &(to[num - j]));
    for (k = 0; k < (num - i); k++)
        to[k] = 0;
    
    r = num;

err:
    if (ctx != NULL){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(buf != NULL){
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }

    return (r);
}

int TPRSA_private_decrypt_NO_PADDING(int flen, const unsigned char *from, TPRSA_KEY *rsa, BIGNUM *ret){
    
    BIGNUM *f;
    int j, num = 0;
    int r = -1;
    BN_CTX *ctx = NULL;
    
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);

    if( !f || !ret ){
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ( flen > num) {
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_DECRYPT, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (BN_bin2bn(from, (int)flen, f) == NULL)
        goto err;
    
    if (BN_ucmp(f, rsa->n) >= 0) {
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_DECRYPT, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

     if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
        if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
            goto err;
    } else {
        BIGNUM local_d;
        BIGNUM *d = NULL;

        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
            d = &local_d;
            BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
        } else
            d = rsa->d;

        if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
            if (!BN_MONT_CTX_set_locked
                (&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
                goto err;
        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n))
            goto err;
    }
    r = 1;

 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return r;
}

int TPRSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, TPRSA_KEY *rsa){

    X509_SIG sig;
    ASN1_TYPE parameter;
    int i, j, ret = 1;
    unsigned char *p, *tmps = NULL;
    const unsigned char *s = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest;
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_NON_FIPS_RSA_METHOD);
        return 0;
    }
#endif
    if ((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign) {
        return rsa->meth->rsa_sign(type, m, m_len, sigret, siglen, rsa);
    }
    /* Special case: SSL signature, just check the length */
    if (type == NID_md5_sha1) {
        if (m_len != SSL_SIG_LENGTH) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_INVALID_MESSAGE_LENGTH);
            return (0);
        }
        i = SSL_SIG_LENGTH;
        s = m;
    } else {
        sig.algor = &algor;
        sig.algor->algorithm = OBJ_nid2obj(type);
        if (sig.algor->algorithm == NULL) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            return (0);
        }
        if (sig.algor->algorithm->length == 0) {
            RSAerr(RSA_F_RSA_SIGN,
                   RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
            return (0);
        }
        parameter.type = V_ASN1_NULL;
        parameter.value.ptr = NULL;
        sig.algor->parameter = &parameter;

        sig.digest = &digest;
        sig.digest->data = (unsigned char *)m; /* TMP UGLY CAST */
        sig.digest->length = m_len;

        i = i2d_X509_SIG(&sig, NULL);
    }
    j = RSA_size(rsa);
    if (i > (j - RSA_PKCS1_PADDING_SIZE)) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return (0);
    }
    if (type != NID_md5_sha1) {
        tmps = (unsigned char *)OPENSSL_malloc((unsigned int)j + 1);
        if (tmps == NULL) {
            RSAerr(RSA_F_RSA_SIGN, ERR_R_MALLOC_FAILURE);
            return (0);
        }
        p = tmps;
        i2d_X509_SIG(&sig, &p);
        s = tmps;
    }

    i = TPRSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

    if (type != NID_md5_sha1) {
        OPENSSL_cleanse(tmps, (unsigned int)j + 1);
        OPENSSL_free(tmps);
    }
    return (ret);
}

int TPRSA_Generate_SHA1(int flen, const unsigned char* from, unsigned char* digest, int tlen){

    int ret = 1;

    if(from == NULL || flen <= 0 || tlen > SHA_DIGEST_LENGTH){
        TPRSAerr(TPRSA_F_TPRSA_GENERATE_SHA1, TPRSA_R_GENERATE_SHA1_FAILED);
        ret = 0;
        goto err;
    }
    
    SHA_CTX sha_ctx;
    SHA_Init(&sha_ctx);
    SHA_Update(&sha_ctx, from, flen);
    SHA_Final(digest, &sha_ctx);
    SHA1(from, flen, digest);

err:
    if (&sha_ctx){
        OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));
    }

    return ret;
}

int TPRSA_Generate_SHA256(int flen, const unsigned char* from, unsigned char* digest, int tlen){

    int ret = 1;

    if(from == NULL || flen <= 0 || tlen > SHA256_DIGEST_LENGTH){
        TPRSAerr(TPRSA_F_TPRSA_GENERATE_SHA1, TPRSA_R_GENERATE_SHA1_FAILED);
        ret = 0;
        goto err;
    }
    
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, from, flen);
    SHA256_Final(digest, &sha_ctx);
    SHA256(from, flen, digest);

err:
    if (&sha_ctx){
        OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));
    }

    return ret;
}


int TPRSA_private_finally_decrypt(unsigned char* to, const BIGNUM* sbignum, const BIGNUM* cbignum, TPRSA_KEY* TPRSA, int padding){

    BIGNUM *ret;
    int j, num = 0, r = -1;
    unsigned char *buf =NULL;
    BN_CTX *ctx = NULL;

    if((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(TPRSA->n);
    buf = (unsigned char*)OPENSSL_malloc(num);

    if( !ret || !buf ){
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_FINALLY_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_mod_mul(ret, sbignum, cbignum, TPRSA->n, ctx);
    j = BN_bn2bin(ret, buf);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
        break;
# ifndef OPENSSL_NO_SHA
    case RSA_PKCS1_OAEP_PADDING:
        r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
        break;
# endif
    case RSA_SSLV23_PADDING:
        r = RSA_padding_check_SSLv23(to, num, buf, j, num);
        break;
    case RSA_NO_PADDING:
        r = RSA_padding_check_none(to, num, buf, j, num);
        break;
    default:
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_FINALLY_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (r < 0)
        TPRSAerr(TPRSA_F_TPRSA_PRIVATE_FINALLY_DECRYPT, RSA_R_PADDING_CHECK_FAILED);


err:
    if(ctx != NULL){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(buf != NULL){
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

int TPRSA_Collaborate_Sign(const unsigned char *client_sign, const unsigned int client_sign_len, 
                            const unsigned char *server_sign, const unsigned int server_sign_len, 
                            unsigned char *sigret, TPRSA_KEY* TPRSA){
    
    BN_CTX* ctx;
    BIGNUM *cbignum, *sbignum, *trsign;
    int r, num, j, ret;
    r = -1;
    num = RSA_size(TPRSA);

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_COLLABORATE_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    cbignum = BN_CTX_get(ctx);
    sbignum = BN_CTX_get(ctx);
    trsign = BN_CTX_get(ctx);

    BN_bin2bn(client_sign, client_sign_len, cbignum);
    BN_bin2bn(server_sign, server_sign_len, sbignum);

    BN_mod_mul(trsign, cbignum, sbignum, TPRSA->n, ctx);

    j = BN_num_bytes(trsign);
    r = BN_bn2bin(trsign, &sigret[num - j]);
    for(int i = 0 ; i < (num - r); i++ ){
        sigret[i] = 0;
    }

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return r;
}

int TPRSA_4096_public_decrypt(int flen, const unsigned char *from, 
                              unsigned char *to, TPRSA_KEY *tprsa, int padding)
{
    BIGNUM *f, *ret;
    int i, num = 0, r = -1;
    unsigned char *p;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(tprsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_MODULUS_TOO_LARGE);
        return -1;
    }

    if (BN_ucmp(tprsa->n, tprsa->e) <= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_BAD_E_VALUE);
        return -1;
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(tprsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto err;
    }

    if (BN_bin2bn(from, flen, f) == NULL)
        goto err;

    if (BN_ucmp(f, tprsa->n) >= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (tprsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked
            (&tprsa->_method_mod_n, CRYPTO_LOCK_RSA, tprsa->n, ctx))
            goto err;

    if (!tprsa->meth->bn_mod_exp(ret, f, tprsa->e, tprsa->n, ctx,
                               tprsa->_method_mod_n))
        goto err;

    if ((padding == RSA_X931_PADDING) && ((ret->d[0] & 0xf) != 12))
        if (!BN_sub(ret, tprsa->n, ret))
            goto err;

    p = buf;
    i = BN_bn2bin(ret, p);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_1(to, num, buf, i, num);
        break;
    case RSA_X931_PADDING:
        r = RSA_padding_check_X931(to, num, buf, i, num);
        break;
    case RSA_NO_PADDING:
        r = RSA_padding_check_none(to, num, buf, i, num);
        break;
    default:
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (r < 0){
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_PADDING_CHECK_FAILED);
    }
        //RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_PADDING_CHECK_FAILED);

 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);                    
}

int TPRSA_4096_public_encrypt(int flen, const unsigned char *from, 
                                unsigned char *to, TPRSA_KEY *tprsa, int padding)
{
    BIGNUM *f, *ret;
    int i, j, k, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(tprsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_MODULUS_TOO_LARGE);
        return -1;
    }

    if (BN_ucmp(tprsa->n, tprsa->e) <= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_BAD_E_VALUE);
        return -1;
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(tprsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
        break;
# ifndef OPENSSL_NO_SHA
    case RSA_PKCS1_OAEP_PADDING:
        i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
        break;
# endif
    case RSA_SSLV23_PADDING:
        i = RSA_padding_add_SSLv23(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    default:
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (i <= 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;

    if (BN_ucmp(f, tprsa->n) >= 0) {
        /* usually the padding functions would catch this */
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (tprsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked
            (&tprsa->_method_mod_n, CRYPTO_LOCK_RSA, tprsa->n, ctx))
            goto err;

    if (!tprsa->meth->bn_mod_exp(ret, f, tprsa->e, tprsa->n, ctx,
                               tprsa->_method_mod_n))
        goto err;

    /*
     * put in leading 0 bytes if the number is less than the length of the
     * modulus
     */
    j = BN_num_bytes(ret);
    i = BN_bn2bin(ret, &(to[num - j]));
    for (k = 0; k < (num - i); k++)
        to[k] = 0;

    r = num;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

int int_TPRSA_4096_verify(int dtype, const unsigned char *m,
                   unsigned int m_len,
                   unsigned char *rm, size_t *prm_len,
                   const unsigned char *sigbuf, size_t siglen, TPRSA_KEY *tprsa)
{
    int i, ret = 0, sigtype;
    unsigned char *s;
    X509_SIG *sig = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_NON_FIPS_RSA_METHOD);
        return 0;
    }
#endif

    if (siglen != (unsigned int)RSA_size(tprsa)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_WRONG_SIGNATURE_LENGTH);
        return (0);
    }

    if ((dtype == NID_md5_sha1) && rm) {
        i = RSA_public_decrypt((int)siglen,
                               sigbuf, rm, tprsa, RSA_PKCS1_PADDING);
        if (i <= 0)
            return 0;
        *prm_len = i;
        return 1;
    }

    s = (unsigned char *)OPENSSL_malloc((unsigned int)siglen);
    if (s == NULL) {
        RSAerr(RSA_F_INT_RSA_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((dtype == NID_md5_sha1) && (m_len != SSL_SIG_LENGTH)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_MESSAGE_LENGTH);
        goto err;
    }
    i = TPRSA_4096_public_decrypt((int)siglen, sigbuf, s, tprsa, RSA_PKCS1_PADDING);

    if (i <= 0){
        goto err;
    }
    /*
     * Oddball MDC2 case: signature can be OCTET STRING. check for correct
     * tag and length octets.
     */
    if (dtype == NID_mdc2 && i == 18 && s[0] == 0x04 && s[1] == 0x10) {
        if (rm) {
            memcpy(rm, s + 2, 16);
            *prm_len = 16;
            ret = 1;
        } else if (memcmp(m, s + 2, 16)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        } else {
            ret = 1;
        }
    } else if (dtype == NID_md5_sha1) {
        /* Special case: SSL signature */
        if ((i != SSL_SIG_LENGTH) || memcmp(s, m, SSL_SIG_LENGTH))
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        else
            ret = 1;
    } else {
        const unsigned char *p = s;
        sig = d2i_X509_SIG(NULL, &p, (long)i);

        if (sig == NULL)
            goto err;

        /* Excess data can be used to create forgeries */
        if (p != s + i || !rsa_check_digestinfo(sig, s, i)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        /*
         * Parameters to the signature algorithm can also be used to create
         * forgeries
         */
        if (sig->algor->parameter
            && ASN1_TYPE_get(sig->algor->parameter) != V_ASN1_NULL) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        sigtype = OBJ_obj2nid(sig->algor->algorithm);

#ifdef RSA_DEBUG
        /* put a backward compatibility flag in EAY */
        fprintf(stderr, "in(%s) expect(%s)\n", OBJ_nid2ln(sigtype),
                OBJ_nid2ln(dtype));
#endif
        if (sigtype != dtype) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_ALGORITHM_MISMATCH);
            goto err;
        }
        if (rm) {
            const EVP_MD *md;
            md = EVP_get_digestbynid(dtype);
            if (md && (EVP_MD_size(md) != sig->digest->length))
                RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_DIGEST_LENGTH);
            else {
                memcpy(rm, sig->digest->data, sig->digest->length);
                *prm_len = sig->digest->length;
                ret = 1;
            }
        } else if (((unsigned int)sig->digest->length != m_len) ||
                   (memcmp(m, sig->digest->data, m_len) != 0)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        } else
            ret = 1;
    }
 err:
    if (sig != NULL)
        X509_SIG_free(sig);
    if (s != NULL) {
        OPENSSL_cleanse(s, (unsigned int)siglen);
        OPENSSL_free(s);
    }
    return (ret);
}

int TPRSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, TPRSA_KEY *tprsa){
    int num = RSA_size(tprsa);
    if(num > 260){
        return (int_TPRSA_4096_verify(dtype, m, m_len, NULL, NULL, sigbuf, RSA_size(tprsa), tprsa));
    }else{
        return (RSA_verify(dtype, m, m_len, sigbuf, RSA_size(tprsa), tprsa));
    }                
}

int rsa_check_digestinfo(X509_SIG *sig, const unsigned char *dinfo,
                                int dinfolen)
{
    unsigned char *der = NULL;
    int derlen;
    int ret = 0;
    derlen = i2d_X509_SIG(sig, &der);
    if (derlen <= 0)
        return 0;
    if (derlen == dinfolen && !memcmp(dinfo, der, derlen))
        ret = 1;
    OPENSSL_cleanse(der, derlen);
    OPENSSL_free(der);
    return ret;
}