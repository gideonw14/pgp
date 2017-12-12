CPP=g++
CPPFLAGS= -std=c++11
FILE=gwalker_pgp.cpp
SUFFIXES= -lgmp -lcrypto
OUTPUT=program
ALICE_PR_KEY=alice_key.pem
#ALICE_PU_KEY=alice_key.pub

all:
	${CPP} ${CPPFLAGS} ${FILE} -o ${OUTPUT} ${SUFFIXES}

keys:
	openssl genpkey -algorithm RSA -out ${ALICE_PR_KEY} -pkeyopt rsa_keygen_bits:2048;
	#openssl rsa -pubout -in ${ALICE_PR_KEY} -out ${ALICE_PU_KEY};
	openssl rsa -text -in ${ALICE_PR_KEY};

clean:
	rm ${ALICE_PR_KEY};
	#rm ${ALICE_PU_KEY};
	rm ${OUTPUT};
