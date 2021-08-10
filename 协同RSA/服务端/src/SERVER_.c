#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tprsa.h>
#include <time.h>
#define MAXBUF 2048


int main(int argc, char **argv)
{
    double op, ed;
    int loop = 0;
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;
 
    myport = 7788;
 
    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, "../server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, "../server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
 
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");
 
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    my_addr.sin_addr.s_addr = INADDR_ANY;
 
    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
        == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");
 
    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");
/**********************************************************************************************************************************************/
    // while (1) {
        SSL *ssl;
        len = sizeof(struct sockaddr);
        /* 等待客户端连上来 */
        if ((new_fd =
             accept(sockfd, (struct sockaddr *) &their_addr,
                    &len)) == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                   inet_ntoa(their_addr.sin_addr),
                   ntohs(their_addr.sin_port), new_fd);
 
        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);
        /* 将连接用户的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);
        /* 建立 SSL 连接 */
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            // break;
        }

        BN_CTX *bnctx = NULL;
        BIGNUM *na, *ea, *eds, *ds,
                *ns, *es;
        bnctx = BN_CTX_new();
        BN_CTX_start(bnctx);
        na = BN_CTX_get(bnctx);
        ea = BN_CTX_get(bnctx);
        eds = BN_CTX_get(bnctx);
        ds = BN_CTX_get(bnctx);
        ns = BN_CTX_get(bnctx);
        es = BN_CTX_get(bnctx);

        TPRSA_KEY *server_key = NULL;
        TPRSA_SK *S = NULL;
        server_key = TPRSAK_new();
        S = TPRSASK_new(server_key);

        TPRSA_SK_Gen_RSA(S, 1024);

        TPRSA_KEY *ss_key = NULL;
        ss_key = TPRSAK_new();

        TPRSA_SK_Get_RSAPK(S, ss_key);

        ns = BN_dup(ss_key->n);
        es = BN_dup(ss_key->e);

        op = clock();
        int ns_len = BN_bn2bin(ns, buf);
        len = SSL_write(ssl, buf, ns_len);
        if( len <= 0){
            perror("发送RSA公钥ns失败\n");
        }

        int es_len = BN_bn2bin(es, buf);
        len = SSL_write(ssl, buf, es_len);
        if( len <= 0){
            perror("发送RSA公钥es失败\n");
        }

        bzero(buf, 1024);
        len = SSL_read(ssl, buf, MAXBUF);
        if(len <= 0){
            perror("接收na失败\n");
        }
        BN_bin2bn(buf, len, na);

        bzero(buf, 1024);
        len = SSL_read(ssl, buf, MAXBUF);
        if(len <= 0){
            perror("接收ea失败\n");
        }
        BN_bin2bn(buf, len, ea);

        bzero(buf, 1024);
        len = SSL_read(ssl, buf, MAXBUF);
        if( len <= 0){
            perror("接收eds失败\n");
        }
        BN_bin2bn(buf, len, eds);

        TPRSA_SK_RSA_Dec(S, ds, eds);

        TPRSA_SK_Set_n(S, na);
        TPRSA_SK_Set_e(S, ea);
        TPRSA_SK_Set_d(S, ds);


        ed = clock();
        double runtime = (ed - op) / CLOCKS_PER_SEC;
        printf("%.7f s\n", runtime);
        int num = RSA_size(server_key);
        unsigned char sha1_digest[SHA_DIGEST_LENGTH] = {0};
        unsigned char *ssign = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * num);
        unsigned int *ssgin_len = (unsigned int *)OPENSSL_malloc(sizeof(unsigned int) * num);

        len = SSL_read(ssl, sha1_digest, sizeof(sha1_digest));
        if (len <= 0)
        {
            perror("消息摘要接收失败\n");
            // break;
        }

        TPRSA_sign(NID_sha1, sha1_digest, sizeof(sha1_digest), ssign, ssgin_len, server_key);

        len = SSL_write(ssl, ssign, *ssgin_len);
        if (len <= 0)
        {
            perror("签名发送失败\n");
            // break;
        }

      finish:
        /* 关闭 SSL 连接 */
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
        SSL_shutdown(ssl);
        /* 释放 SSL */
        SSL_free(ssl);
        /* 关闭 socket */
        close(new_fd);
    //   }
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}