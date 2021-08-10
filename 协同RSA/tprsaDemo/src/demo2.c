#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/tprsa.h>

int main(){
    double op,ed, op1, ed1;
    op = clock();
    BN_CTX *ctx = NULL;
    BIGNUM *na, *ea, *eds, *ds;
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    na = BN_CTX_get(ctx);
    ea = BN_CTX_get(ctx);
    eds = BN_CTX_get(ctx);
    ds = BN_CTX_get(ctx);

    TPRSA_KEY *client_key = NULL;
    TPRSA_KEY *server_key = NULL;
    TPRSA_SK *C = NULL;
    TPRSA_SK *S = NULL;
    client_key = TPRSAK_new();
    server_key = TPRSAK_new();

    C = TPRSASK_new(client_key);
    S = TPRSASK_new(server_key);

    TPRSA_SK_Gen_RSA(S, 4096);

    TPRSA_KEY *ss_key = NULL;
    ss_key = TPRSAK_new();

    TPRSA_SK_Get_RSAPK(S, ss_key);

    TPRSA_SK_Set_RSAPK(C, ss_key);
    
    //TPRSA_SK_Gen_Key_Eds(C, 2048, na, ea, eds);
    TPRSA_SK_Gen_Key_ds(C, 4096, na, ea, ds);
    TPRSA_SK_Get_n(C, na);
    TPRSA_SK_Get_e(C, ea);
    
    //TPRSA_SK_RSA_Dec(S, ds, eds);

    TPRSA_SK_Set_n(S, na);
    TPRSA_SK_Set_e(S, ea);
    TPRSA_SK_Set_d(S, ds);

    int num = RSA_size(client_key);
    unsigned char plantext[] = "hello world!";
    int plen = sizeof(plantext) - 1;
    unsigned char sha1_digest[SHA_DIGEST_LENGTH] = {0};
    unsigned char to[512] = {0};
    unsigned char *csign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
    unsigned int *csign_len = (unsigned int *)OPENSSL_malloc(sizeof(unsigned int) * num);
    unsigned char *ssign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
    unsigned int *ssign_len = (unsigned int *)OPENSSL_malloc(sizeof(unsigned int) * num);
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH] = {0};
    unsigned char *sha256_csign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
    unsigned int *sha256_csign_len = (unsigned int *)OPENSSL_malloc(sizeof(unsigned int) * num);
    unsigned char *sha256_ssign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
    unsigned int *sha256_ssign_len = (unsigned int *)OPENSSL_malloc(sizeof(unsigned int) * num);
    unsigned char sha256_to[512] = {0};

    TPRSA_Generate_SHA1(plen, plantext, sha1_digest, sizeof(sha1_digest));
    TPRSA_sign(NID_sha1, sha1_digest, sizeof(sha1_digest), csign, csign_len, client_key);
    TPRSA_sign(NID_sha1, sha1_digest, sizeof(sha1_digest), ssign, ssign_len, server_key);
    TPRSA_Collaborate_Sign(csign, *csign_len, ssign, *ssign_len, to, client_key);
    int phase = 0;
    if (phase = TPRSA_verify(NID_sha1, sha1_digest, sizeof(sha1_digest), to, client_key))
    {
        printf("SHA1协同签名验证成功！\n");
    }
    else
    {
        printf("SHA1协同签名验证失败！\n");
    }
    TPRSA_Generate_SHA256(plen, plantext, sha256_digest, sizeof(sha256_digest));
    TPRSA_sign(NID_sha256, sha256_digest, sizeof(sha256_digest), sha256_csign, sha256_csign_len, server_key);
    TPRSA_sign(NID_sha256, sha256_digest, sizeof(sha256_digest), sha256_ssign, sha256_ssign_len, client_key);
    TPRSA_Collaborate_Sign(sha256_csign, *sha256_csign_len, sha256_ssign, *sha256_ssign_len, sha256_to, client_key);
    int phase2 = 0;
    if (phase2 = TPRSA_verify(NID_sha256, sha256_digest, sizeof(sha256_digest), sha256_to, client_key))
    {
        printf("SHA256协同签名验证成功！\n");
    }
    else
    {
        printf("SHA256协同签名验证失败！\n");
    }
    ed = clock();
    double runtime = (ed - op) / CLOCKS_PER_SEC;
    printf("%.7f s\n", runtime);

    printf("Plantext:%s\n",  plantext);
    unsigned char cip_client[512]={0};
    unsigned char message[512]={0};
    BIGNUM* c_to_bignum = BN_CTX_get(ctx);
    BIGNUM* s_to_bignum = BN_CTX_get(ctx);
    TPRSA_CLIENT_public_encrypt(sizeof(plantext), plantext, cip_client, client_key, RSA_PKCS1_PADDING);
    TPRSA_CLIENT_private_decrypt(num, cip_client, client_key, c_to_bignum);
    TPRSA_SERVER_private_decrypt(num, cip_client, server_key, s_to_bignum);
    TPRSA_private_finally_decrypt(message, s_to_bignum, c_to_bignum, server_key, RSA_PKCS1_PADDING);
    printf("Plantext:%s\n", message);
    
}