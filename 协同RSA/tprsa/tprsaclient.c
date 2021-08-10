#include <openssl/tprsa.h>

#ifndef OPENSSL_NO_TPRSA
int LEN_OF_CRT;

struct TPRSA_client
{
    BIGNUM* ta;
    BIGNUM* phi_ta;
    BIGNUM **pta;
    BIGNUM **crt;
    BIGNUM *conpr;
    TPRSA_KEY* key;
    BIGNUM* e_phi_na;
    BIGNUM* eta_a;
    BIGNUM* rho_a;
    BIGNUM* c_phi_ns;
    TPRSA_PAILLIER *Pkey;
};

TPRSA_CLIENT* TPRSA_CLIENT_new(TPRSA_KEY* key, int type){
    TPRSA_CLIENT* ret = NULL;
    if(type != 1024 && type != 2048 && type != 4096){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_NEW, TPRSA_R_UNKNOW_LEN_TYPE);
        goto err;
    }
    ret = (TPRSA_CLIENT*)OPENSSL_malloc(sizeof(TPRSA_CLIENT));
    if(!ret){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret->key = key;
    ret->Pkey = (TPRSA_PAILLIER*)OPENSSL_malloc(sizeof(TPRSA_PAILLIER));
    switch (type)
    {
    case 1024:
        PRIMES_ARRAY = primes_1024_bits;
        LEN_OF_ARRAY = 75;
        PRIMES_BITS = 512;
        LEN_OF_PRE = 68;
        LEN_OF_CRT = 37;
        ret->pta = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    case 2048:
        PRIMES_ARRAY = primes_2048_bits;
        LEN_OF_ARRAY = 131;
        PRIMES_BITS = 1024;
        LEN_OF_PRE = 128;
        LEN_OF_CRT = 65;
        ret->pta = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    case 4096:
        PRIMES_ARRAY = primes_4096_bits;
        LEN_OF_ARRAY = 233;
        PRIMES_BITS = 2048;
        LEN_OF_PRE = 200;
        LEN_OF_CRT = 116;
        ret->pta = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_PRE);
        ret->crt = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_CRT);
        break;
    default:
        break;
    }

err:
    return ret;
}

void TPRSA_CLIENT_Free(TPRSA_CLIENT* r){
    if(r != NULL){
        if(r->key != NULL){
            TPRSAK_Free(r->key);
            r->key = NULL;
        }
        if(r->Pkey){
            OPENSSL_free(r->Pkey);
            r->Pkey = NULL;
        }
        if(r->c_phi_ns){
            BN_free(r->c_phi_ns);
        }
        if(r->e_phi_na){
            BN_free(r->e_phi_na);
            r->e_phi_na = NULL;
        }
        if(r->eta_a){
            BN_free(r->eta_a);
            r->eta_a = NULL;
        }
        if(r->phi_ta){
            BN_free(r->phi_ta);
            r->phi_ta = NULL;
        }
        if(r->rho_a){
            BN_free(r->rho_a);
            r->rho_a = NULL;
        }
        if(r->ta){
            BN_free(r->ta);
            r->ta = NULL;
        }
        if(r->crt){
            OPENSSL_free(r->crt);
            r->crt = NULL;
        }
        if(r->conpr){
            BN_free(r->conpr);
            r->conpr = NULL;
        }
        if(r->pta){
            OPENSSL_free(r->pta);
            r->pta = NULL;
        }
        OPENSSL_free(r);
        r = NULL;
    }
}

int TPRSA_CLIENT_Precompiled(TPRSA_CLIENT *r){
    if(!TPRSA_CLIENT_Set_Continuous_Primes(r) ||
       !TPRSA_CLIENT_Set_CRT(r) ||
       !TPRSA_CLIENT_Set_Primes_Array(r) ||
       !TPRSA_CLIENT_Set_t_phi(r))
       {
           TPRSAerr(TPRSA_F_TPRSA_CLIENT_PRECOMPILED, TPRSA_R_PRECOMPILED_FAILED);
           return 0;
       }
       return 1;
}

int TPRSA_CLIENT_Set_Continuous_Primes(TPRSA_CLIENT* r){
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

int TPRSA_CLIENT_Set_CRT(TPRSA_CLIENT *r){
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
    for(int i = 1; i < LEN_OF_ARRAY; i++){
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

int TPRSA_CLIENT_Set_t_phi(TPRSA_CLIENT* r){

    int ret = -1;
    if( !r ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_T_PHI, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(r->ta = BN_new()) || !(r->phi_ta = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_T_PHI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret = BN_generate_prime_ex(r->ta, 511, 1, NULL, NULL, NULL);
    r->phi_ta = BN_dup(r->ta);
    BN_sub_word(r->phi_ta, 1);
    BN_div_word(r->phi_ta, 2);

err:
    return (ret);
}

int TPRSA_CLIENT_Set_Primes_Array(TPRSA_CLIENT* r){
    BN_CTX *ctx = NULL;
    BIGNUM *CRT_Pi, *CRT_Pr;
    int ret = -1;
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PRIMES_ARRAY, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PRIMES_ARRAY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    CRT_Pi = BN_CTX_get(ctx);
    CRT_Pr = BN_CTX_get(ctx);
    for(int i = 0; i < LEN_OF_PRE; i++){
        if(!(r->pta[i] = BN_new()) ){
            TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PRIMES_ARRAY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BN_zero(r->pta[i]);
        int k = 0;
        for(int j = 1; j < LEN_OF_ARRAY; j++){
            BN_set_word(CRT_Pi,PRIMES_ARRAY[j]);
            BN_rand_range(CRT_Pr, CRT_Pi);
            while(BN_num_bits(CRT_Pr) == 0){
                BN_rand_range(CRT_Pr, CRT_Pi);
            }
            BN_mod_mul(CRT_Pi,CRT_Pr,r->crt[k], r->conpr,ctx);
            BN_mod_add(r->pta[i],r->pta[i],CRT_Pi, r->conpr,ctx);
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

int TPRSA_CLIENT_Set_pkP(TPRSA_CLIENT* r, TPRSA_PAILLIER* k){

    if(!r || !k ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PKP, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if( !(r->Pkey->g = BN_new()) || !(r->Pkey->N = BN_new()) || !(r->Pkey->N_2 = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PKP, ERR_R_MALLOC_FAILURE);
        return 0;
    }   

    r->Pkey->g = BN_dup(k->g);
    r->Pkey->N = BN_dup(k->N);
    r->Pkey->N_2 = BN_dup(k->N_2);
    return 1;
}


BIGNUM* TPRSA_CLIENT_pkP_Enc(TPRSA_CLIENT* r, BIGNUM* ret, const BIGNUM* m){
    TPRSA_Paillier_Enc_Message(m, ret, r->Pkey);
    return ret;
}

const BIGNUM* TPRSA_CLIENT_get_ta(TPRSA_CLIENT* r){    
    return r->ta;
}

const BIGNUM* TPRSA_CLIENT_get_phi_ta(TPRSA_CLIENT *r){
    return r->phi_ta;
}

int TPRSA_CLIENT_Set_pa(TPRSA_CLIENT *r, int i){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_PA, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    r->key->p = BN_dup(r->pta[i]);
    return 1;
}

int TPRSA_CLIENT_Set_qa(TPRSA_CLIENT *r, int i){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_QA, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    r->key->q = BN_dup(r->pta[i]);
    return 1;
}

const BIGNUM* TPRSA_CLIENT_get_qa(TPRSA_CLIENT *r){
    return r->key->q;
}

const BIGNUM* TPRSA_CLIENT_get_pa(TPRSA_CLIENT *r){
    return r->key->p;
}

const BIGNUM* TPRSA_CLIENT_get_N_2(TPRSA_CLIENT *r){
    return r->Pkey->N_2;
}

int TPRSA_CLIENT_Check_pv(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* tp){
    BN_CTX* ctx;
    BIGNUM *ret, *v;
    int ret_ = -1;
    
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_CHECK_V, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);

    BN_one(ret);
    BN_sub(ret, r->key->p, ret);
    BN_mul(ret, r->phi_ta, ret, ctx);
    BN_mod_exp(ret, a, ret, tp, ctx);
    BN_mod_exp(v, b, r->phi_ta, tp, ctx);
    BN_mod_mul(v, ret, v, tp, ctx);
    if(BN_num_bits(v)==1){
        ret_ = 1;
    }else{
        ret_ = 0;
    }

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret_);

}

int TPRSA_CLIENT_Check_qv(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* tq){
    BN_CTX* ctx;
    BIGNUM *ret, *v;
    int ret_ = -1;
    
    if(!(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_CHECK_V, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);

    BN_one(ret);
    BN_sub(ret, r->key->q, ret);
    BN_mul(ret, r->phi_ta, ret, ctx);
    BN_mod_exp(ret, a, ret, tq, ctx);
    BN_mod_exp(v, b, r->phi_ta, tq, ctx);
    BN_mod_mul(v, ret, v, tq, ctx);
    if(BN_num_bits(v)==1){
        ret_ = 1;
    }else{
        ret_ = 0;
    }

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret_);
}

int TPRSA_CLIENT_COMPUTE_CTP(TPRSA_CLIENT* r, BIGNUM *ctp, const BIGNUM* cts, const BIGNUM* ctps){
    BN_CTX* ctx = NULL;
    BIGNUM *ret, *ret_;
    int i = 0;

    if( !r || !cts || !ctps ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COMPUTER_CTP, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COMPUTER_CTP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    ret_ = BN_CTX_get(ctx);

    BN_mul(ret, r->key->p, r->ta, ctx);
    BN_mod_exp(ret, cts, ret, r->Pkey->N_2, ctx);
    BN_mod_exp(ret_, ctps, r->ta, r->Pkey->N_2, ctx);
    BN_mod_mul(ctp, ret, ret_, r->Pkey->N_2, ctx);
    i = 1;

err:

    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (i);
}

int TPRSA_CLIENT_COMPUTE_CTQ(TPRSA_CLIENT* r, BIGNUM* ctq, const BIGNUM* cts, const BIGNUM* ctps){
    BN_CTX* ctx = NULL;
    BIGNUM *ret, *ret_;
    int i = 0;

    if( !r || !cts || !ctps ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COMPUTER_CTQ, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(ctx = BN_CTX_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COMPUTER_CTQ, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    ret_ = BN_CTX_get(ctx);

    BN_mul(ret, r->key->q, r->ta, ctx);
    BN_mod_exp(ret, cts, ret, r->Pkey->N_2, ctx);
    BN_mod_exp(ret_, ctps, r->ta, r->Pkey->N_2, ctx);
    BN_mod_mul(ctq, ret, ret_, r->Pkey->N_2, ctx);

    i = 1;

err:

    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return (i);

}

const BIGNUM* TPRSA_CLIENT_pkP_Enc_MULT_TWO(TPRSA_CLIENT* r, const BIGNUM* a, const BIGNUM* b){

    BN_CTX* ctx = NULL;
    BIGNUM *ret, *ret_ = NULL;

    if( !r || !a || !b ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_PKP_ENC_MULT_TWO, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(ctx = BN_CTX_new()) || !(ret = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_PKP_ENC_MULT_TWO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret_ = BN_CTX_get(ctx);

    BN_mul(ret_, a, b, ctx);
    TPRSA_CLIENT_pkP_Enc(r, ret, ret_);

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

const TPRSA_PAILLIER* TPRSA_CLIENT_get_pkP(TPRSA_CLIENT* r){
    return r->Pkey;
}

const BIGNUM* TPRSA_CLIENT_COM_Cn(TPRSA_CLIENT* r, BIGNUM* cn, const BIGNUM* cp, const BIGNUM* cq){
    BN_CTX* ctx = NULL;
    BIGNUM *cn_, *ca;

    if(!r || !cp || !cq ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_CN, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    
    if( !(ctx = BN_CTX_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_CN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    cn_ = BN_CTX_get(ctx);
    ca = BN_CTX_get(ctx);

    ca = (BIGNUM*)TPRSA_CLIENT_pkP_Enc_MULT_TWO(r, r->key->p, r->key->q);
    BN_mod_exp(cn, cp, r->key->q, r->Pkey->N_2, ctx);
    BN_mod_exp(cn_, cq, r->key->p, r->Pkey->N_2, ctx);
    BN_mod_mul(cn, cn, cn_, r->Pkey->N_2, ctx);
    BN_mod_mul(cn, cn, ca, r->Pkey->N_2, ctx);

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return cn;
}

int TPRSA_CLIENT_Set_n(TPRSA_CLIENT*r, const BIGNUM* n){

    if( !r || !n ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_N, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }

    if( !(r->key->n = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_N, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }

    r->key->n = BN_dup(n);
    return 1;
}

const BIGNUM* TPRSA_CLIENT_get_n(TPRSA_CLIENT* r){
    return r->key->n;
}

int TPRSA_CLIENT_Set_e(TPRSA_CLIENT*r){
    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_E, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    
    if( !(r->key->e = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_E, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    BN_generate_prime_ex(r->key->e, 511, 0, NULL, NULL, NULL);
    return 1;
}

int TPRSA_CLIENT_Set0_e(TPRSA_CLIENT*r, const BIGNUM* e){
    if(!r||!e){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET0_E, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->key->e = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET0_E, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    r->key->e = BN_dup(e);
    return 1;

}

const BIGNUM* TPRSA_CLIENT_get_e(TPRSA_CLIENT* r){
    return r->key->e;
}

const BIGNUM* TPRSA_CLIENT_get_random(int bits){

    BIGNUM* ret = NULL;
    if( !bits ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_GET_RANDOM, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }

    if( !(ret = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_GET_RANDOM, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_zero(ret);
    while( BN_num_bits(ret) == 0){
        BN_rand(ret, bits, -1, -1);
    }

err:

    return ret;
}

const BIGNUM* TPRSA_CLIENT_get_random_range(const BIGNUM* e){
    BIGNUM* ret = NULL;
    if(!e){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_GET_RANDOM_RANGE, TPRSA_R_PARAMS_NULL_ERROR);
        goto err;
    }
    
    if( !(ret = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_GET_RANDOM_RANGE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_rand_range(ret, e);
    while( BN_num_bits(ret) == 0){
        BN_rand_range(ret, e);
    }

err:

    return ret;
}

int TPRSA_CLIENT_COM_EPHINA(TPRSA_CLIENT* r){

    if(!r){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_EPHINA, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }

    if(!(r->e_phi_na = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_EPHINA, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    r->e_phi_na = BN_dup(r->key->n);
    BN_sub_word(r->e_phi_na, 1);
    BN_div_word(r->e_phi_na, 2);
    BN_sub(r->e_phi_na, r->e_phi_na, r->key->p);
    BN_sub(r->e_phi_na, r->e_phi_na, r->key->q);
    BN_add_word(r->e_phi_na, 1);

    return 1;
}

const BIGNUM* TPRSA_CLIENT_get_EPHINA(TPRSA_CLIENT* r){
    return r->e_phi_na;
}

int TPRSA_CLIENT_COM_C_MPHIN(TPRSA_CLIENT* r, BIGNUM* ret, const BIGNUM* c_phi_ns){
    int ret_ = -1;
    BN_CTX *ctx;
    BIGNUM *c_phi_na, *r1;
    if( !(ctx = BN_CTX_new()) || !(r->eta_a = BN_new()) || !(r->c_phi_ns = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_C_MPHIN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    c_phi_na = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);

    r->c_phi_ns = BN_dup(c_phi_ns);
    r1 = (BIGNUM*)TPRSA_CLIENT_get_random_range(r->key->e);
    TPRSA_CLIENT_pkP_Enc(r, c_phi_na, TPRSA_CLIENT_get_EPHINA(r));
    BN_mod_mul(c_phi_na, c_phi_na, c_phi_ns, r->Pkey->N_2, ctx);
    BN_mod_exp(ret, c_phi_na, r1, r->Pkey->N_2, ctx);
    BN_sub(r->eta_a, r->key->e, r1);
    
    ret_ = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret_);
}

int TPRSA_CLIENT_COM_cr3(TPRSA_CLIENT* r, BIGNUM* cr3, const BIGNUM* c_eta_s){
    int ret = -1;
    BN_CTX* ctx = NULL;
    BIGNUM *cr2, *r2 = NULL;

    if(!(ctx = BN_CTX_new()) || !(r->rho_a = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_CR3, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    cr2 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);

    r2 = (BIGNUM*)TPRSA_CLIENT_get_random_range(r->key->e);
    TPRSA_CLIENT_pkP_Enc(r, cr2, r2);
    BN_mod_exp(cr3, c_eta_s, r->eta_a, r->Pkey->N_2, ctx);
    BN_mod_mul(cr3, cr3, cr2, r->Pkey->N_2,ctx);
    BN_sub(r->rho_a, r->key->e, r2);

    ret = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}


int TPRSA_CLIENT_COM_cs(TPRSA_CLIENT* r, BIGNUM* cs, const BIGNUM* c_rho_s){
    BN_CTX* ctx = NULL;
    BIGNUM *mdA, *r_, *cr, *cs_ = NULL;
    int ret = -1;
    if (!(ctx = BN_CTX_new()) || !(r->key->d = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_COM_CS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    mdA = BN_CTX_get(ctx);
    r_ = BN_CTX_get(ctx);
    cr = BN_CTX_get(ctx);
    cs_ = BN_CTX_get(ctx);
    mdA = (BIGNUM*)TPRSA_CLIENT_get_random(2*PRIMES_BITS - 16);
    BN_mul(r_, r->rho_a, r->e_phi_na, ctx);
    BN_add_word(r_, 1);
    BN_sub(r_, r_, mdA);
    TPRSA_CLIENT_pkP_Enc(r, cr, r_);
    BN_mod_exp(cs, c_rho_s, r->e_phi_na, r->Pkey->N_2, ctx);
    BN_mod_mul(cs, cs, cr, r->Pkey->N_2, ctx);
    BN_mod_exp(cs_, r->c_phi_ns, r->rho_a, r->Pkey->N_2, ctx);
    BN_mod_mul(cs, cs, cs_, r->Pkey->N_2, ctx);
    BN_div(r->key->d, NULL, mdA, r->key->e, ctx);

    ret = 1;
err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

const BIGNUM* TPRSA_CLIENT_get_da(TPRSA_CLIENT* r){
    return r->key->d;
}

int TPRSA_CLIENT_Set_da(TPRSA_CLIENT* r, const BIGNUM* da){
    if(!r || !da){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_DA, TPRSA_R_PARAMS_NULL_ERROR);
        return 0;
    }
    if(!(r->key->d = BN_new())){
        TPRSAerr(TPRSA_F_TPRSA_CLIENT_SET_DA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    r->key->d = BN_dup(da);
    return 1;
}

int TPRSA_CLIENT_public_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    int num = RSA_size(rsa);
    if(num > 260){
        return (TPRSA_4096_public_encrypt(flen, from, to, rsa, padding));
    }else{
        return (rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding));
    }
}

int TPRSA_CLIENT_private_encrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    return TPRSA_private_encrypt(flen, from, to, rsa, padding);
}

int TPRSA_CLIENT_public_decrypt(int flen, const unsigned char *from, unsigned char *to, TPRSA_KEY* rsa, int padding){
    int num = RSA_size(rsa);
    if(num > 260){
        return (TPRSA_4096_public_decrypt(flen, from, to, rsa, padding));
    }else{
        return (rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding));
    }
}

int TPRSA_CLIENT_private_decrypt(int flen, const unsigned char *from, TPRSA_KEY* rsa, BIGNUM* ret){
    return TPRSA_private_decrypt_NO_PADDING(flen, from, rsa, ret);
}

const TPRSA_KEY* TPRSA_CLIENT_get_rsa_key(TPRSA_CLIENT* r){
    return r->key;
}


#endif