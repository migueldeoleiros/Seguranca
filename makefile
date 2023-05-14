# Segurança Informática - trabalho 2
#   Grupo: 6
#   Nuno Infante 55411
#   Miguel López 59436
#   Marco Martins 41938
#   João Nobre 51659

JC = javac
JFLAGS = -d bin -cp bin

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLIENT_CLASSES = \
	src/client/Command.java \
	src/myCloud.java

SERVER_CLASSES = \
	src/myCloudServer.java

default: classes

classes: client server

client: $(CLIENT_CLASSES:.java=.class)

server: $(SERVER_CLASSES:.java=.class)

client-keystores:
	mkdir -p certificates
	keytool -genkeypair -keysize 2048 -alias maria -keyalg rsa -dname "CN=none, OU=none, O=none, L=none, ST=none, C=none" -keystore certificates/maria.keystore -storetype PKCS12 -storepass 123123
	keytool -export -keystore certificates/maria.keystore -alias maria -file maria.cer -storepass 123123
	keytool -genkeypair -keysize 2048 -alias jose -keyalg rsa -dname "CN=none, OU=none, O=none, L=none, ST=none, C=none" -keystore certificates/jose.keystore -storetype PKCS12 -storepass 321321
	keytool -export -keystore certificates/jose.keystore -alias jose -file jose.cer -storepass 321321

server-certificates:
	mkdir -p serverFiles
	keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -dname "CN=none, OU=none, O=none, L=none, ST=none, C=none" -keystore serverFiles/keystore.server -storetype PKCS12 -storepass 123123
	keytool -exportcert -alias server -file cert.server -keystore serverFiles/keystore.server -storepass 123123
	echo "yes" | keytool -importcert -alias server -keystore truststore.client -file cert.server -storetype PKCS12 -storepass 123123
	rm -f cert.server

all: classes server-certificates client-keystores

clean:
	$(RM) bin/*.class
	$(RM) -r serverFiles/*
	$(RM) -r certificates/*
	$(RM) truststore.client cert.server
