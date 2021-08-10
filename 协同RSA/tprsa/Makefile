#
# OpenSSL/crypto/tprsa/Makefile
#

DIR=    tprsa
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST= tprsatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=tprsa.c tprsa_err.c tprsaclient.c tprsaserver.c tprsatrust.c  tprsask.c
LIBOBJ=tprsa.o tprsa_err.o tprsaclient.o tprsaserver.o tprsatrust.o  tprsask.o

SRC= $(LIBSRC)

EXHEADER= tprsa.h 
HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

tprsaclient.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
tprsaclient.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tprsaclient.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tprsaclient.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tprsaclient.o: ../../include/openssl/objects.h
tprsaclient.o: ../../include/openssl/opensslconf.h
tprsaclient.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tprsaclient.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tprsaclient.o: ../../include/openssl/symhacks.h ../../include/openssl/tprsa.h
tprsaclient.o: tprsaclient.c
tprsa_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
tprsa_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tprsa_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tprsa_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tprsa_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tprsa_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tprsa_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tprsa_err.o: ../../include/openssl/symhacks.h ../../include/openssl/tprsa.h
tprsa_err.o: tprsa_err.c
tprsa.o: ../../e_os.h ../../include/openssl/asn1.h
tprsa.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tprsa.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tprsa.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tprsa.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
tprsa.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tprsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tprsa.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tprsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tprsa.o: ../../include/openssl/sha.h ../../include/openssl/rsa.h
tprsa.o: ../../include/openssl/tprsa.h
tprsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tprsa.o: ../cryptlib.h tprsa.c

tprsaserver.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
tprsaserver.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tprsaserver.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tprsaserver.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tprsaserver.o: ../../include/openssl/objects.h
tprsaserver.o: ../../include/openssl/opensslconf.h
tprsaserver.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tprsaserver.o: ../../include/openssl/tprsa.h tprsaserver.c
tprsask.o: ../../include/openssl/tprsa.h tprsask.c
