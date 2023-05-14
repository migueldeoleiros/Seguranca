# Segurança Informática - trabalho 2
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659

O projeto é composto por tres ficheiros, o cliente composto por "myCloud.java" e
"client/Command.java" e o servidor "myCloudServer.java".

# Para compilar os ficheiros

O makefile tem várias opções para configurar o programa:

"make server" e "make client" compilarão o código do servidor e do cliente, respectivamente,
executar ambos em conjunto será o mesmo que executar "make".

Para gerar os certificados necessários para a ligação TLS, temos o comando "make server-certificates". 

Para gerar keystores e certificados de teste para os utilizadores, temos o comando "make client-keystores",
criando ficheiros para dois utilizadores: maria, com a palavra-passe 123123 e jose, com a palavra-passe 321321

Para fazer o setup completo podemos usar o comando "make all"


# Para executar o programa

Primeiramente, é necessário executar o servidor com:
    java -cp bin myCloudServer <port> 

O servidor solicitará a criação do MAC para o ficheiro de palavras-passe, ao iniciar o servidor,
se o ficheiro já existir, ou ao criar o primeiro utilizador.
A palavra-passe utilizada na criação do MAC será solicitada na próxima vez que o servidor for iniciado.

Uma vez que o servidor esteja em execução, temos que criar um utilizador usando o keystore e o certificado
que criámos anteriormente, é importante usar a mesma plavra-passe do keystore:
    myCloud -a <serverAddress> -au <username> <password> <certificado>

Depois de criar o utilizador, pode executar o cliente de qualquer uma das seguintes formas:
    myCloud -a <serverAddress> -u <username> -p <password> -c {<filenames>}+
    myCloud -a <serverAddress> -u <username> -p <password> -s {<filenames>}+
    myCloud -a <serverAddress> -u <username> -p <password> -e {<filenames>}+
    myCloud -a <serverAddress> -u <username> -p <password> -g {<filenames>}+

O servidor vai criar uma pasta chamada "serverFiles" com os ficheiros armazenados.
O cliente vai criar uma pasta "certificates" com os certificados dos utilizadores.
