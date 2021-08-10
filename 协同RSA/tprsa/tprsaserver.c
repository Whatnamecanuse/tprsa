
#include <openssl/tprsa.h>

#ifndef OPENSSL_NO_TPRSA

int LEN_OF_CRT;

struct TPRSA_server
{
    TPRSA_PAILLIER* key;
    TPRSA_KEY* Rkey;
    BIGNUM **pts;
    BIGNUM **crt;
    BIGNUM *conpr;
    BIGNUM *ts;
    BIGNUM *phi_ts;
    BIGNUM* rho_s;
    BIGNUM* e_phi_s;
    BIGNUM* e_phi_ps;
    BIGNUM* e_phi_ns;
 };

TPRSA_SERVER* TPRSA_SERVER_new(TPRSA_KEY* key, int type){
    TPRSA_SERVER* ret = NULL;
    if(type != 1024 && type != 2048 && type != 4096){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_NEW, TPRSA_R_UNKNOW_LEN_TYPE);
        goto err;
    }
    ret = (TPRSA_SERVER*)OPENSSL_malloc(sizeof(TPRSA_SERVER));
    ret->key = (TPRSA_PAILLIER*)OPENSSL_malloc(sizeof(TPRSA_PAILLIER));
    ret->Rkey = key;
    switch (type)
    {
    case 1024:
        PRIMES_ARRAY = primes_1024_bits;
        LEN_OF_ARRAY = 75;
        PRIMES_BITS = 512;
        LEN_OF_PRE = 68;
        LEN_OF_CRT = 38;
        ret->pts = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    case 2048:
        PRIMES_ARRAY = primes_2048_bits;
        LEN_OF_ARRAY = 131;
        PRIMES_BITS = 1024;
        LEN_OF_PRE = 128;
        LEN_OF_CRT = 66;
        ret->pts = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    case 4096:
        PRIMES_ARRAY = primes_4096_bits;
        LEN_OF_ARRAY = 233;
        PRIMES_BITS = 2048;
        LEN_OF_PRE = 200;
        LEN_OF_CRT = 117;
        ret->pts = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    default:
        break;
    }
err:
    return ret;
}

void TPRSA_SERVER_Free(TPRSA_SERVER* r){
    if(r){
        if(r->key){
            TPRSAK_Free(r->Rkey);
            r->key = NULL;
        }
        if(r->key){
            OPENSSL_free(r->key);
            r->Rkey = NULL;
        }
        if(r->e_phi_ns){
            BN_free(r->e_phi_ns);
            r->e_phi_ns = NULL;
        }
        if(r->e_phi_ps){
            BN_free(r->e_phi_ps);
            r->e_phi_ps = NULL;
        }
        if(r->e_phi_s){
            BN_free(r->e_phi_s);
            r->e_phi_s = NULL;
        }
        if(r->rho_s){
            BN_free(r->rho_s);
            r->rho_s = NULL;
        }
        if(r->ts){
            BN_free(r->ts);
            r->ts = NULL;
        }
        if(r->conpr){
            BN_free(r->conpr);
            r->conpr = NULL;
        }
        if(r->crt){
            OPENSSL_free(r->crt);
            r->crt = NULL;
        }
        if(r->pts){
            OPENSSL_free(r->pts);
            r->pts = NULL;
        }
        OPENSSL_free(r);
        r = NULL;
    }
}

int TPRSA_SERVER_Precompiled(TPRSA_SERVER *r){
    if(!TPRSA_SERVER_Set_Continuous_Primes(r) ||
       !TPRSA_SERVER_Set_CRT(r) ||
       !TPRSA_SERVER_Set_Primes_Array(r) ||
       !TPRSA_SERVER_Set_Paillier_key(r) ||
       !TPRSA_SERVER_Set_t_phi(r))
       {
           TPRSAerr(TPRSA_F_TPRSA_SERVER_PRECOMPILED, TPRSA_R_PRECOMPILED_FAILED);
           return 0;
       }
       return 1;

}

int TPRSA_SERVER_Set_Continuous_Primes(TPRSA_SERVER* r){
    BN_CTX* ctx = NULL;
    BIGNUM* primes_ = NULL;
    int ret = -1;

    if( !(ctx = BN_CTX_new()) || !(r->conpr = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_GENERATE_CONTINUOUS_PRIMES, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    primes_ = BN_CTX_get(ctx);
    BN_one(r->conpr);
    for(int i = 0; i < LEN_OF_ARRAY;i++){
        BN_set_word(primes_,*(PRIMES_ARRAY+i));
        BN_mul(r->conpr,r->conpr,primes_,ctx);
    }
    ret= 1;

err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return (ret);
}

int TPRSA_SERVER_Set_CRT(TPRSA_SERVER *r){
    BN_CTX *ctx;
    BIGNUM *CRT_Pi, *CRT_Mi, *CRT_Mi_Inverse;
    int ret = -1;
    
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_PRE_CRT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    CRT_Pi = BN_CTX_get(ctx);
    CRT_Mi = BN_CTX_get(ctx);
    CRT_Mi_Inverse = BN_CTX_get(ctx);
    int k = 0;
    for(int i = 0; i < LEN_OF_ARRAY; i++){
        BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
        BN_div(CRT_Mi, NULL, r->conpr, CRT_Pi, ctx);
        BN_mod_inverse(CRT_Mi_Inverse, CRT_Mi, CRT_Pi, ctx);
        if(!(r->crt[k] = BN_new())){
            TPRSAerr(TPRSA_F_TPRSA_PRE_CRT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BN_mul(r->crt[k], CRT_Mi, CRT_Mi_Inverse, ctx);
        i++;
        k++;
    }
    ret = 1;
err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}


int TPRSA_SERVER_Set_Paillier_key(TPRSA_SERVER* r){
    int ret = -1;
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PAILLIER_KEY, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if( !(r->key->g = BN_new()) || !(r->key->N = BN_new()) || !(r->key->N_2 = BN_new()) || !(r->key->lambda = BN_new()) || !(r->key->mu = BN_new()))
    {
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PAILLIER_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret = TPRSA_Paillier_Generate_Key(r->key);

err:
    return (ret);
}

int TPRSA_SERVER_Set_Paillier_key2(TPRSA_SERVER* r){
    int ret = -1;
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PAILLIER_KEY, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if( !(r->key->g = BN_new()) || !(r->key->N = BN_new()) || !(r->key->N_2 = BN_new()) || !(r->key->lambda = BN_new()) || !(r->key->mu = BN_new()))
    {
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PAILLIER_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret = TPRSA_Paillier_Generate_Key2(r->key);

err:
    return (ret);
}

int TPRSA_SERVER_Set_t_phi(TPRSA_SERVER* r){

    int ret = -1;
    if( !r ){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_T_PHI, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(r->ts = BN_new()) || !(r->phi_ts = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_T_PHI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret = BN_generate_prime_ex(r->ts, 511, 1, NULL, NULL, NULL);
    r->phi_ts = BN_dup(r->ts);
    BN_sub_word(r->phi_ts, 1);
    BN_div_word(r->phi_ts, 2);

err:
    return (ret);
}

int TPRSA_SERVER_Set_Primes_Array(TPRSA_SERVER* r){
    BN_CTX *ctx = NULL;
    BIGNUM *CRT_Pi, *CRT_Pr;
    int ret = -1;
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PRIMES_ARRAY, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PRIMES_ARRAY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    CRT_Pi = BN_CTX_get(ctx);
    CRT_Pr = BN_CTX_get(ctx);

    for(int i = 0; i < LEN_OF_PRE; i++){
        if(!(r->pts[i] = BN_new()) ){
            TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PRIMES_ARRAY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BN_zero(r->pts[i]);
        int k = 0;
        for(int j = 0; j < LEN_OF_ARRAY; j++){
            BN_set_word(CRT_Pi,PRIMES_ARRAY[j]);
            if(j == 0){
                BN_set_word(CRT_Pr, 3);

            }
            else{
                BN_rand_range(CRT_Pr, CRT_Pi);
                while(BN_num_bits(CRT_Pr) == 0){
                    BN_rand_range(CRT_Pr, CRT_Pi);
                }
            }
            BN_mod_mul(CRT_Pi,CRT_Pr,r->crt[k], r->conpr,ctx);
            BN_mod_add(r->pts[i], r->pts[i],CRT_Pi, r->conpr,ctx);
            k++;
            j++;
        }
    }    
    ret = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

int TPRSA_SERVER_pkP_Enc(TPRSA_SERVER* r, BIGNUM* ret, const BIGNUM* m){
    return (TPRSA_Paillier_Enc_Message(m, ret, r->key));
}

int TPRSA_SERVER_skP_Dec(TPRSA_SERVER* r, BIGNUM* ret, const BIGNUM* c){
    return (TPRSA_Paillier_Dec_Ciphertext(ret, c, r->key));
}

const BIGNUM* TPRSA_SERVER_get_ts(TPRSA_SERVER* r){
    return r->ts;
}

const BIGNUM* TPRSA_SERVER_get_phi_ts(TPRSA_SERVER *r){
    return r->phi_ts;
}

int TPRSA_SERVER_Set_ps(TPRSA_SERVER *r,int i){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_PS, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    r->Rkey->p = BN_dup(r->pts[i]);
    return 1;
}

int TPRSA_SERVER_Set_qs(TPRSA_SERVER *r, int i){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_QS, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    r->Rkey->q = BN_dup(r->pts[i]);
    return 1;
}

const BIGNUM* TPRSA_SERVER_get_qs(TPRSA_SERVER *r){
    return r->Rkey->q;
}

const BIGNUM* TPRSA_SERVER_get_ps(TPRSA_SERVER *r){
    return r->Rkey->p;
}
TPRSA_PAILLIER* TPRSA_SERVER_get_pkP(TPRSA_SERVER* r){ 
    TPRSA_PAILLIER *ret = NULL;
    ret = OPENSSL_malloc(sizeof(TPRSA_PAILLIER));
    ret->g = BN_dup(r->key->g);
    ret->N = BN_dup(r->key->N);
    ret->N_2 = BN_dup(r->key->N_2);
    return ret;
}

const BIGNUM* TPRSA_SERVER_get_random(int bits){

    BIGNUM* ret = NULL;
    if( !bits ){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_GET_RANDOM, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(ret = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_GET_RANDOM, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_zero(ret);
    while( BN_num_bits(ret) == 0){
        BN_rand(ret, bits, -1, -1);
    }

err:

    return ret;
}

int TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_PS(TPRSA_SERVER* r, const BIGNUM* tp){
    BN_CTX* ctx = NULL;
    BIGNUM *rd, *ret = NULL;
    int ret_ = -1;

    if(!(ctx = BN_CTX_new()) || !(r->e_phi_s = BN_new()) || !(r->e_phi_ps = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_PS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    rd = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    rd = (BIGNUM*)TPRSA_SERVER_get_random(PRIMES_BITS);
    BN_mod_exp(r->e_phi_s, rd, r->phi_ts, tp, ctx);
    BN_mul(ret, r->phi_ts, r->Rkey->p, ctx);
    BN_mod_exp(r->e_phi_ps, rd, ret, tp, ctx);
    ret_ = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret_);
}

int TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_QS(TPRSA_SERVER* r, const BIGNUM* tp){
    BN_CTX* ctx = NULL;
    BIGNUM *rd, *ret = NULL;
    int ret_ = -1;

    if(!(ctx = BN_CTX_new()) || !(r->e_phi_s = BN_new()) || !(r->e_phi_ps = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COMPUTE_E_PHI_S_E_PHI_QS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    rd = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    rd = (BIGNUM*)TPRSA_SERVER_get_random(PRIMES_BITS);
    BN_mod_exp(r->e_phi_s, rd, r->phi_ts, tp, ctx);
    BN_mul(ret, r->phi_ts, r->Rkey->q, ctx);
    BN_mod_exp(r->e_phi_ps, rd, ret, tp, ctx);
    ret_ = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret_);
}


const BIGNUM* TPRSA_SERVER_get_e_phi_s(TPRSA_SERVER* r){
    return r->e_phi_s;
}

const BIGNUM* TPRSA_SERVER_get_e_phi_ps(TPRSA_SERVER* r){
    return r->e_phi_ps;
}

int TPRSA_SERVER_DEC_COM_n(TPRSA_SERVER* r, const BIGNUM* cn){
    BN_CTX* ctx;
    BIGNUM* temp;
    int ret = -1;

    if(!(ctx = BN_CTX_new()) || !(r->Rkey->n = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_DEC_COM_N, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    temp = BN_CTX_get(ctx);
    TPRSA_SERVER_skP_Dec(r, temp, cn);
    BN_mul(r->Rkey->n, TPRSA_SERVER_get_ps(r), TPRSA_SERVER_get_qs(r), ctx);
    BN_add(r->Rkey->n, r->Rkey->n, temp);
    ret = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return (ret);
}

const BIGNUM* TPRSA_SERVER_get_n(TPRSA_SERVER* r){
    return r->Rkey->n;
}

int TPRSA_SERVER_COM_EPHINS(TPRSA_SERVER* r){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_EPHINS, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->e_phi_ns = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_EPHINS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    r->e_phi_ns = BN_dup(r->Rkey->n);
    BN_sub_word(r->e_phi_ns, 1);
    BN_div_word(r->e_phi_ns, 2);
    BN_sub(r->e_phi_ns, r->e_phi_ns, r->Rkey->p);
    BN_sub(r->e_phi_ns, r->e_phi_ns, r->Rkey->q);
    BN_add_word(r->e_phi_ns, 1);

    return 1;
}

const BIGNUM* TPRSA_SERVER_get_EPHINS(TPRSA_SERVER* r){
    return r->e_phi_ns;
}

int TPRSA_SERVER_Set_e(TPRSA_SERVER* r, const BIGNUM* e){
    if(!r || !e){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_E,TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->Rkey->e = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_E, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    r->Rkey->e = BN_dup(e);
    return 1;
}

int TPRSA_SERVER_Set_ds(TPRSA_SERVER*r, const BIGNUM* ds){
    if(!r || !ds){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_DS, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->Rkey->d = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_SET_DS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    r->Rkey->d = BN_dup(ds);
    return 1;
}

int TPRSA_SERVER_Set_n(TPRSA_SERVER*r, const BIGNUM* n){
    if(!r||!n){
        TPRSAerr(TRRAS_F_TPRSA_SERVER_SET_N, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->Rkey->n = BN_new())){
        TPRSAerr(TRRAS_F_TPRSA_SERVER_SET_N, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    r->Rkey->n = BN_dup(n);
    return 1;
}

const BIGNUM* TPRSA_SERVER_get_e(TPRSA_SERVER* r){
    return r->Rkey->e;
}

int TPRSA_SERVER_COM_CETAS(TPRSA_SERVER* r, BIGNUM *c_eta_s, const BIGNUM* cm_phi_n){
    BN_CTX* ctx = NULL;
    int ret = 0;
    if(!r || !cm_phi_n){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_CETAS, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_EPHINS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    TPRSA_SERVER_skP_Dec(r, c_eta_s, cm_phi_n);
    BN_mod_inverse(c_eta_s, c_eta_s, r->Rkey->e, ctx);
    TPRSA_SERVER_pkP_Enc(r, c_eta_s, c_eta_s);
    ret = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

int TPRSA_SERVER_COM_c_rho_s(TPRSA_SERVER* r, BIGNUM* c_rho_s, const BIGNUM* cr3){
    BN_CTX* ctx = NULL;
    BIGNUM* r3;
    int ret = -1;
    if(!r || !c_rho_s || !cr3){
        TPRSAerr(TPRSA_F_SERVER_COM_C_RHO_S, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if(!(ctx = BN_CTX_new()) || !(r->rho_s = BN_new())){
        TPRSAerr(TPRSA_F_SERVER_COM_C_RHO_S, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    r3 = BN_CTX_get(ctx);
    TPRSA_SERVER_skP_Dec(r, r3, cr3);
    BN_mod(r->rho_s, r3, r->Rkey->e, ctx);
    TPRSA_SERVER_pkP_Enc(r, c_rho_s, r->rho_s);
    ret = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

int TPRSA_SERVER_COM_ds(TPRSA_SERVER* r, const BIGNUM* cs){
    BN_CTX* ctx = NULL;
    BIGNUM *r4, *mdS, *div;
    int ret = -1;
    if(!r || !cs){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_DS, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    if(!(ctx = BN_CTX_new()) || !(r->Rkey->d = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_SERVER_COM_DS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    r4 = BN_CTX_get(ctx);
    mdS = BN_CTX_get(ctx);
    div = BN_CTX_get(ctx);

    TPRSA_SERVER_skP_Dec(r, r4, cs);
    BN_mul(mdS, r->rho_s, r->e_phi_ns, ctx);
    BN_add(mdS, r4, mdS);
    BN_div(r->Rkey->d, div, mdS, r->Rkey->e, ctx);

    if(BN_num_bits(div)){
        BN_add_word(r->Rkey->d, 1);
    }

    ret = 1;
err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

const BIGNUM* TPRSA_SERVER_get_ds(TPRSA_SERVER* r){
    return r->Rkey->d;
}

int TPRSA_SERVER_public_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    int num = RSA_size(rsa);
    if(num > 260){
        return (TPRSA_4096_public_encrypt(flen, from, to, rsa, padding));
    }else{
        return (rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding));
    }
}

int TPRSA_SERVER_private_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    return TPRSA_private_encrypt(flen, from, to, rsa, padding);
}

int TPRSA_SERVER_public_decrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    int num = RSA_size(rsa);
    if(num > 260){
        return (TPRSA_4096_public_decrypt(flen, from, to, rsa, padding));
    }else{
        return (rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding));
    }
}

int TPRSA_SERVER_private_decrypt(int flen, const unsigned char *from, TPRSA_KEY* rsa, BIGNUM* ret){
    return TPRSA_private_decrypt_NO_PADDING(flen, from, rsa, ret);
}

const TPRSA_KEY* TPRSA_SERVER_get_rsa_key(TPRSA_SERVER* r){
    return r->Rkey;
}

#endif