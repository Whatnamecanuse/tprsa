#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tprsa.h>
#include <time.h>

#define MAXBUF 2048
#define SIGNBUF 128

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
       X509_free(cert);
    } else
        printf("无证书信息！\n");
}
 
int main(int argc, char **argv)
{
    double op, ed;
    op = clock();
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;
 
    // if (argc != 3) {
    //     printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口\n\t比如:\t%s 127.0.0.1 80\n此程序用来从某个"
    //          "IP 地址的服务器某个端口接收最多 MAXBUF 个字节的消息",
    //          argv[0], argv[0]);
    //     exit(0);
    // }
 
    /* SSL 库初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
 
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
 
    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    // dest.sin_port = htons(atoi(argv[2]));
    dest.sin_port = htons(7788);
    if (inet_aton("127.0.0.1", (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");
 
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
 
    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
/********************************************************************************************************************************/

    BN_CTX *bnctx = NULL;
    BIGNUM *na, *ea, *eds, *ds, *ns, *es;
    bnctx = BN_CTX_new();
    BN_CTX_start(bnctx);
    na = BN_CTX_get(bnctx);
    ea = BN_CTX_get(bnctx);
    eds = BN_CTX_get(bnctx);
    ds = BN_CTX_get(bnctx);
    ns = BN_CTX_get(bnctx);    
    es = BN_CTX_get(bnctx);

    TPRSA_KEY *client_key = NULL;
    TPRSA_SK *C = NULL;
    client_key = TPRSAK_new();
    C = TPRSASK_new(client_key);

    TPRSA_KEY *ss_key = NULL;
    ss_key = TPRSAK_new();

    bzero(buffer, 1024);
    len = SSL_read(ssl, buffer, MAXBUF);
    if(len <= 0){
        perror("ns接收失败\n");
    }
    BN_bin2bn(buffer, len, ns);

    bzero(buffer, 1024);
    len = SSL_read(ssl, buffer, MAXBUF);
    if( len <= 0){
        perror("es接收失败\n");
    }
    BN_bin2bn(buffer, len, es);
    
    ss_key->n = BN_new();
    ss_key->e = BN_new();
    ss_key->n = BN_dup(ns);
    ss_key->e = BN_dup(es);

    TPRSA_SK_Set_RSAPK(C, ss_key);

    TPRSA_SK_Gen_Key(C, 1024, na, ea, eds);

    TPRSA_SK_Get_n(C, na);
    TPRSA_SK_Get_e(C, ea);

    int na_len = BN_bn2bin(na, buffer);
    len = SSL_write(ssl, buffer, na_len);
    if( len <= 0){
        perror("发送na失败\n");
    }

    int ea_len = BN_bn2bin(ea, buffer);
    len = SSL_write(ssl, buffer, ea_len);
    if( len <= 0){
        perror("发送ea失败\n");
    }

    int eds_len = BN_bn2bin(eds, buffer);
    len = SSL_write(ssl, buffer, eds_len);
    if( len <= 0){
        perror("发送eds失败\n");
    }



    

    int num = RSA_size(client_key);
    unsigned char plantext[] = "hello world！";
    int plen = sizeof(plantext) - 1;
    unsigned char sha1_digest[SHA_DIGEST_LENGTH] = {0};
    unsigned char to[512] = {0};
    unsigned char *csign = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*num);
    unsigned int *csgin_len = (unsigned int*)OPENSSL_malloc(sizeof(unsigned int)*num);
    TPRSA_Generate_SHA1(plen, plantext, sha1_digest, sizeof(sha1_digest));
    TPRSA_sign(NID_sha1, sha1_digest, sizeof(sha1_digest), csign, csgin_len,  client_key);

    len = SSL_write(ssl, sha1_digest, sizeof(sha1_digest));
    if(len <= 0){
        perror("发送消息摘要失败\n");
    }
    
    unsigned char *ssign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
    unsigned int *ssgin_len = (unsigned int*)OPENSSL_malloc(sizeof(unsigned int)*num);    
    bzero(ssign, SIGNBUF);
    len = SSL_read(ssl, ssign, SIGNBUF);
    if(len <= 0){
        perror("服务器签名接收失败\n");
    }
    TPRSA_Collaborate_Sign(csign, *csgin_len, ssign, len, to, client_key);
    if(TPRSA_verify(NID_sha1, sha1_digest, sizeof(sha1_digest), to, client_key)){
        printf("sha1协同签名验证成功!\n");
    }else{
        printf("sha1协同签名验证失败!\n");
    }
    ed = clock();
    double runtime = (ed-op)/CLOCKS_PER_SEC;
    printf("%.7f s\n", runtime);
  finish:
    /* 关闭连接 */
    // OPENSSL_free(pkP);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}