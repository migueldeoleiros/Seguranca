# Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659

O projeto é composto por dois ficheiros, o cliente "myCloud.java" e o servidor "myCloudServer.java".

# Para compilar os ficheiros, é necessário executar:
    javac src/myCloud.java -d bin
    javac src/myCloudServer.java -d bin


# Para executar o programa

Antes de executar o programa, precisa de criar um keystore com o nome "keystore.maria" e a palavra-passe "123123" e adicionar um par de chaves assimétricas para o alias "maria".
    keytool -genkeypair -keysize 2048 -alias maria -keyalg rsa -keystore keystore.maria -storetype PKCS12 -storepass 123123

Primeiramente, é necessário executar o servidor com:
    java -cp bin myCloudServer <port> 

Uma vez que o servidor esteja em execução, pode executar o cliente de qualquer uma das seguintes formas:
    java -cp bin myCloud -a <serverAddress:port> -c {<filenames>}+
    java -cp bin myCloud -a <serverAddress:port> -s {<filenames>}+
    java -cp bin myCloud -a <serverAddress:port> -e {<filenames>}+
    java -cp bin myCloud -a <serverAddress:port> -g {<filenames>}+

O programa vai criar uma pasta chamada "serverFiles" com os ficheiros armazenados.
