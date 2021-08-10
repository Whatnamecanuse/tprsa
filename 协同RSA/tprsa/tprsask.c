#include <openssl/tprsa.h>

#ifndef OPENSSL_NO_TPRSA

BIGNUM **CRT;

struct TPRSA_sk
{
    TPRSA_KEY *Tkey;
    TPRSA_KEY *Skey;
};


TPRSA_SK *TPRSASK_new(TPRSA_KEY *key){
    TPRSA_SK *ret = NULL;
    ret = (TPRSA_SK*)OPENSSL_malloc(sizeof(TPRSA_SK));
    ret->Tkey = key;
    ret->Skey = TPRSAK_new();
    return ret;
}

void TPRSASK_free(TPRSA_SK *sk){
    if(sk){
        if(sk->Tkey){
            OPENSSL_free(sk->Tkey);
            sk->Tkey = NULL;
        }
        if(sk->Skey){
            OPENSSL_free(sk->Skey);
            sk->Skey = NULL;
        }
        OPENSSL_free(sk);
        sk = NULL;
    }
}

int TPRSA_SK_Gen_RSA(TPRSA_SK *sk, int type){
    BN_CTX *ctx;
    BIGNUM *q, *p, *phi;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    q = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    phi = BN_CTX_get(ctx);
    int bits = (type + 8) / 2;
    BN_generate_prime_ex(q, bits, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(p ,bits, 0, NULL, NULL, NULL);
    sk->Skey->e = BN_new();
    BN_generate_prime_ex(sk->Skey->e, 511, 0, NULL, NULL, NULL);
    sk->Skey->n = BN_new();
    BN_mul(sk->Skey->n, p, q, ctx);
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(phi, p, q, ctx);
    sk->Skey->d = BN_new();
    BN_mod_inverse(sk->Skey->d, sk->Skey->e, phi, ctx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

int TPRSA_SK_Get_RSAPK(TPRSA_SK *sk, TPRSA_KEY *Skey){
    int ret = -1;
    Skey->n = BN_new();
    Skey->e = BN_new();
    Skey->n = BN_dup(sk->Skey->n);
    Skey->e = BN_dup(sk->Skey->e);
    ret = 1;
    return ret;
}


int TPRSA_SK_Set_RSAPK(TPRSA_SK *sk, TPRSA_KEY *Skey){
    int ret = -1;
    sk->Skey->n = BN_new();
    sk->Skey->e = BN_new();
    sk->Skey->n = BN_dup(Skey->n);
    sk->Skey->e = BN_dup(Skey->e);
    ret = 1;
    return ret;
}

int TPRSA_SK_Gen_Key_Eds(TPRSA_SK *sk, int type, BIGNUM *na, BIGNUM *ea, BIGNUM *eds){
    int ret = 0;
    switch (type)
    {
    case 1024:
        LEN_OF_ARRAY = 75;
        PRIMES_ARRAY = primes_1024_bits;
        break;
    case 2048:
        LEN_OF_ARRAY = 131;
        PRIMES_ARRAY = primes_2048_bits;
        break;
    case 4096:
        LEN_OF_ARRAY = 233;
        PRIMES_ARRAY = primes_4096_bits;
        break;
    default:
        break;
    }
    
    BN_CTX *ctx = NULL;
    BIGNUM *primes_, *cp, *p, *q, *d, *ds, *phi,
                        *CRT_Pi, *CRT_Pr, *CRT_Mi, *CRT_Mi_Inverse;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    primes_ = BN_CTX_get(ctx);
    cp = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    d = BN_CTX_get(ctx);
    ds = BN_CTX_get(ctx);
    phi = BN_CTX_get(ctx);
    CRT_Pi = BN_CTX_get(ctx);
    CRT_Pr = BN_CTX_get(ctx);
    CRT_Mi = BN_CTX_get(ctx);
    CRT_Mi_Inverse = BN_CTX_get(ctx);

    CRT = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_ARRAY);

    BN_one(cp);
    for(int i = 0; i < LEN_OF_ARRAY;i++){
        BN_set_word(primes_,*(PRIMES_ARRAY+i));
        BN_mul(cp, cp, primes_,ctx);
    }

    for(int i = 0; i < LEN_OF_ARRAY; i++)
    {
        BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
        BN_div(CRT_Mi, NULL, cp, CRT_Pi, ctx);
        BN_mod_inverse(CRT_Mi_Inverse, CRT_Mi, CRT_Pi, ctx);
        CRT[i] = BN_new();
        BN_mul(CRT[i], CRT_Mi, CRT_Mi_Inverse, ctx);
    }

    sk->Tkey->n = BN_new();
    BN_zero(sk->Tkey->n);
    while(BN_num_bits(sk->Tkey->n) != type){
        if(BN_num_bits(sk->Tkey->n) != type && (BN_is_prime_ex(p, 1, ctx, NULL) && BN_is_prime_ex(q, 1, ctx, NULL))){
            if(BN_num_bits(p) == type / 2){
                BN_zero(q);
            }else if(BN_num_bits(q) == type/2){
                BN_zero(p);
            }else{
                BN_zero(q);
                BN_zero(p);
            }
        }
        while(!(BN_is_prime_ex(p, 1, ctx, NULL) && BN_is_prime_ex(q, 1, ctx, NULL))){
            if(!BN_is_prime_ex(p, 1, ctx, NULL)){
                BN_zero(p);
                for(int i = 0; i < LEN_OF_ARRAY; i++){
                    BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
                    if(i == 0){
                        BN_set_word(CRT_Pr, 3);
                    }else{
                        BN_rand_range(CRT_Pr, CRT_Pi);
                        while(BN_num_bits(CRT_Pr) == 0){
                            BN_rand_range(CRT_Pr, CRT_Pi);
                        }
                    }
                    BN_mod_mul(CRT_Pi, CRT_Pr, CRT[i], cp, ctx);
                    BN_mod_add(p, p, CRT_Pi, cp, ctx);
                }
            }
            if(!BN_is_prime_ex(q, 1, ctx, NULL)){
                BN_zero(q);
                for (int i = 0; i < LEN_OF_ARRAY; i++)
                {
                    BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
                    if (i == 0)
                    {
                        BN_set_word(CRT_Pr, 3);
                    }
                    else
                    {
                        BN_rand_range(CRT_Pr, CRT_Pi);
                        while (BN_num_bits(CRT_Pr) == 0)
                        {
                            BN_rand_range(CRT_Pr, CRT_Pi);
                        }
                    }
                    BN_mod_mul(CRT_Pi, CRT_Pr, CRT[i], cp, ctx);
                    BN_mod_add(q, q, CRT_Pi, cp, ctx);
                }
            }
        }
        BN_mul(sk->Tkey->n, p, q, ctx);
    }

    sk->Tkey->e = BN_new();
    BN_generate_prime_ex(sk->Tkey->e, 512, -1, NULL, NULL, NULL);
    
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(phi, p, q, ctx);

    BN_mod_inverse(d, sk->Tkey->e, phi, ctx);

    sk->Tkey->d = BN_new();
    BN_rand(sk->Tkey->d, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    while(BN_num_bits(sk->Tkey->d) == 0){
        BN_rand(sk->Tkey->d, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    }

    BN_mod_sub(ds, d, sk->Tkey->d, phi, ctx);

    BN_mod_exp(eds, ds, sk->Skey->e, sk->Skey->n, ctx);
    
    BN_copy(na, sk->Tkey->n);
    BN_copy(ea,sk->Tkey->e);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
    return ret;
}

int TPRSA_SK_Gen_Key_ds(TPRSA_SK *sk, int type, BIGNUM *na, BIGNUM *ea, BIGNUM *ds){
    int ret = 0;
    switch (type)
    {
    case 1024:
        LEN_OF_ARRAY = 75;
        PRIMES_ARRAY = primes_1024_bits;
        break;
    case 2048:
        LEN_OF_ARRAY = 131;
        PRIMES_ARRAY = primes_2048_bits;
        break;
    case 4096:
        LEN_OF_ARRAY = 233;
        PRIMES_ARRAY = primes_4096_bits;
        break;
    default:
        break;
    }
    
    BN_CTX *ctx = NULL;
    BIGNUM *primes_, *cp, *p, *q, *d, *phi,
                        *CRT_Pi, *CRT_Pr, *CRT_Mi, *CRT_Mi_Inverse;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    primes_ = BN_CTX_get(ctx);
    cp = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    d = BN_CTX_get(ctx);
    phi = BN_CTX_get(ctx);
    CRT_Pi = BN_CTX_get(ctx);
    CRT_Pr = BN_CTX_get(ctx);
    CRT_Mi = BN_CTX_get(ctx);
    CRT_Mi_Inverse = BN_CTX_get(ctx);

    CRT = OPENSSL_malloc(sizeof(BIGNUM)*LEN_OF_ARRAY);

    BN_one(cp);
    for(int i = 0; i < LEN_OF_ARRAY;i++){
        BN_set_word(primes_,*(PRIMES_ARRAY+i));
        BN_mul(cp, cp, primes_,ctx);
    }

    for(int i = 0; i < LEN_OF_ARRAY; i++)
    {
        BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
        BN_div(CRT_Mi, NULL, cp, CRT_Pi, ctx);
        BN_mod_inverse(CRT_Mi_Inverse, CRT_Mi, CRT_Pi, ctx);
        CRT[i] = BN_new();
        BN_mul(CRT[i], CRT_Mi, CRT_Mi_Inverse, ctx);
    }

    sk->Tkey->n = BN_new();
    BN_zero(sk->Tkey->n);
    while(BN_num_bits(sk->Tkey->n) != type){
        if(BN_num_bits(sk->Tkey->n) != type && (BN_is_prime_ex(p, 1, ctx, NULL) && BN_is_prime_ex(q, 1, ctx, NULL))){
            if(BN_num_bits(p) == type / 2){
                BN_zero(q);
            }else if(BN_num_bits(q) == type/2){
                BN_zero(p);
            }else{
                BN_zero(q);
                BN_zero(p);
            }
        }
        while(!(BN_is_prime_ex(p, 1, ctx, NULL) && BN_is_prime_ex(q, 1, ctx, NULL))){
            if(!BN_is_prime_ex(p, 1, ctx, NULL)){
                BN_zero(p);
                for(int i = 0; i < LEN_OF_ARRAY; i++){
                    BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
                    if(i == 0){
                        BN_set_word(CRT_Pr, 3);
                    }else{
                        BN_rand_range(CRT_Pr, CRT_Pi);
                        while(BN_num_bits(CRT_Pr) == 0){
                            BN_rand_range(CRT_Pr, CRT_Pi);
                        }
                    }
                    BN_mod_mul(CRT_Pi, CRT_Pr, CRT[i], cp, ctx);
                    BN_mod_add(p, p, CRT_Pi, cp, ctx);
                }
            }
            if(!BN_is_prime_ex(q, 1, ctx, NULL)){
                BN_zero(q);
                for (int i = 0; i < LEN_OF_ARRAY; i++)
                {
                    BN_set_word(CRT_Pi, PRIMES_ARRAY[i]);
                    if (i == 0)
                    {
                        BN_set_word(CRT_Pr, 3);
                    }
                    else
                    {
                        BN_rand_range(CRT_Pr, CRT_Pi);
                        while (BN_num_bits(CRT_Pr) == 0)
                        {
                            BN_rand_range(CRT_Pr, CRT_Pi);
                        }
                    }
                    BN_mod_mul(CRT_Pi, CRT_Pr, CRT[i], cp, ctx);
                    BN_mod_add(q, q, CRT_Pi, cp, ctx);
                }
            }
        }
        BN_mul(sk->Tkey->n, p, q, ctx);
    }

    sk->Tkey->e = BN_new();
    BN_generate_prime_ex(sk->Tkey->e, 512, -1, NULL, NULL, NULL);
    
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(phi, p, q, ctx);

    BN_mod_inverse(d, sk->Tkey->e, phi, ctx);

    sk->Tkey->d = BN_new();
    BN_rand(sk->Tkey->d, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    while(BN_num_bits(sk->Tkey->d) == 0){
        BN_rand(sk->Tkey->d, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    }

    BN_mod_sub(ds, d, sk->Tkey->d, phi, ctx);
    
    BN_copy(na, sk->Tkey->n);
    BN_copy(ea,sk->Tkey->e);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_free(CRT);
    ret = 1;
    return ret;
}

int TPRSA_SK_RSA_Dec(TPRSA_SK *sk, BIGNUM *ret, const BIGNUM *m){
    int r = -1;
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BN_mod_exp(ret, m, sk->Skey->d, sk->Skey->n, ctx);
    r = 1;
    return r;
}
int TPRSA_SK_Get_e(TPRSA_SK *sk, BIGNUM *e){
    if(!sk->Tkey->e){
        return 0;
    }
    BN_copy(e, sk->Tkey->e);
    return 1;
}

int TPRSA_SK_Get_n(TPRSA_SK *sk, BIGNUM *n){
    if(!sk->Tkey->n){
        return 0;
    }
    BN_copy(n, sk->Tkey->n);
    return 1;
}

int TPRSA_SK_Get_d(TPRSA_SK *sk, BIGNUM *d){
    if(!sk->Tkey->d){
        return 0;
    }
    BN_copy(d, sk->Tkey->d);
    return 1;
}

int TPRSA_SK_Set_n(TPRSA_SK *sk, const BIGNUM *n){
    if(!sk || !n){
        return 0;
    }
    sk->Tkey->n = BN_new();
    sk->Tkey->n = BN_dup(n);
    return 1;
}

int TPRSA_SK_Set_e(TPRSA_SK *sk, const BIGNUM *e){
    if(!sk || !e){
        return 0;
    }
    sk->Tkey->e = BN_new();
    sk->Tkey->e = BN_dup(e);
    return 1;
}

int TPRSA_SK_Set_d(TPRSA_SK *sk, const BIGNUM *d){
    if(!sk || !d){
        return 0;
    }
    sk->Tkey->d = BN_new();
    sk->Tkey->d = BN_dup(d);
    return 1;
}

int TPRSA_SK_DivKey_ds(TPRSA_SK *sk, BIGNUM *na, BIGNUM *ea, BIGNUM *ds){
    int ret = 0;
    BN_CTX *ctx;
    BIGNUM *da;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    da = BN_CTX_get(ctx);

    BN_rand(da, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    while(BN_num_bits(sk->Tkey->d) == 0){
        BN_rand(da, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    }

    BN_sub(ds, sk->Tkey->d, da);
    na = BN_dup(sk->Tkey->n);
    ea = BN_dup(sk->Tkey->e);
    sk->Tkey->d = BN_dup(da);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
    return ret;

}

int TPRSA_SK_DivKey_Eds(TPRSA_SK *sk, BIGNUM *na, BIGNUM *ea, BIGNUM *eds){
    int ret = 0;
    BN_CTX *ctx;
    BIGNUM *da;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    da = BN_CTX_get(ctx);


    BN_rand(da, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    while(BN_num_bits(sk->Tkey->d) == 0){
        BN_rand(da, BN_num_bits(sk->Tkey->n)/2, -1, -1);
    }

    BN_sub(eds, sk->Tkey->d, da);

    BN_mod_exp(eds, eds, sk->Skey->e, sk->Skey->n, ctx);
    
    na = BN_dup(sk->Tkey->n);
    ea = BN_dup(sk->Tkey->e);
    sk->Tkey->d = BN_dup(da);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
    return ret;

}
#endif