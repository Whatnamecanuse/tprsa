#include <openssl/tprsa.h>

#ifndef OPENSSL_NO_TPRSA

struct TPRSA_dealer
{
    TPRSA_KEY* key;
    BIGNUM* ds;
    BIGNUM* da;
};

TPRSA_DEALER* TPRSA_DEALER_new(TPRSA_KEY* key){
    TPRSA_DEALER *ret = (TPRSA_DEALER*)OPENSSL_malloc(sizeof(TPRSA_DEALER));
    if(!ret){
        TPRSAerr(TPRSA_F_TPRSA_DEALER_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->key = key;
    ret->da = NULL;
    ret->ds = NULL;
    return ret;
}

void TPRSA_DEALER_Free(TPRSA_DEALER* d){
    if(d != NULL){
        if(d->key){
            TPRSAK_Free(d->key);
            d->key = NULL;
        }
        if(d->da){
            BN_free(d->da);
        }
        if(d->ds){
            BN_free(d->ds);
        }
        OPENSSL_free(d);
        d = NULL;
    }
}

int TPRSA_DEALER_TRSK(TPRSA_DEALER* d){
    BN_CTX *ctx = NULL;
    BIGNUM *ret, *phi, *ran, *temp = NULL;
    int r = -1;

    if( !(ctx = BN_CTX_new()) || !(d->da = BN_new()) || !(d->ds = BN_new()) ){
        TPRSAerr(TPRSA_F_TPRSA_DEALER_TRSK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    ret = BN_CTX_get(ctx);
    phi = BN_CTX_get(ctx);
    ran = BN_CTX_get(ctx);
    temp = BN_CTX_get(ctx);

    BN_one(phi);
    BN_one(ret);
    BN_sub(ret, d->key->p, phi);
    BN_sub(phi, d->key->q, phi);
    BN_mul(phi, phi, ret, ctx);

    BN_set_word(temp ,PRIMES_BITS);
    BN_set_word(ran, 2);
    BN_exp(ran, ran, temp, ctx);

    BN_rand_range(d->da, (const BIGNUM*)ran);
    while(BN_num_bits(d->da) == 0){
        BN_rand_range(d->da, (const BIGNUM*)ran);
    }

    BN_mod_sub(d->ds, d->key->d, d->da, phi, ctx);

    r = 1;

err:
    if(ctx){
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (r);
}

int TPRSA_DEALER_Gen_Key(TPRSA_DEALER* d){
    int i = 0;
     i = TPRSA_key_gen(d->key);
     return (i);
}

#endif