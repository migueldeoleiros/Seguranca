/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.CipherOutputStream;

import java.io.FileInputStream;  	
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class myCloud {

    public static void main(String[] args) throws Exception {
        String address = "localhost";
        int port = 9999;
        ArrayList<String> filenames = new ArrayList<String>();
        String mode = "";

        // Check if arguments were provided
        if (args.length == 0) {
            System.out.println("Usage: myCloud -a <serverAddress> -c {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -s {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -e {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -g {<filenames>}+");
            return;
        }

        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-a")) {
                // Get server address
                String[] parts = args[i+1].split(":");
                address = parts[0];
                port = Integer.parseInt(parts[1]);
                i++;
            } else if (args[i].equals("-c") || args[i].equals("-s") || args[i].equals("-e") || args[i].equals("-g")) {
                // Get command (c, s, e, or g)
                mode = args[i].substring(1);
                i++;
                // Get filenames
                while (i < args.length && !args[i].startsWith("-")) {
                    filenames.add(args[i]);
                    i++;
                }
                i--;
            }
        }

        //connect to socket
		Socket socket = new Socket(address, port);

        // Perform action based on command
        switch (mode) {
            case "c":
                // TODO cifra
            	sendEncryptedFile(socket, filenames);
                break;
            case "s":
                // TODO assina
                break;
            case "e":
                // TODO cifra e assina
                break;
            case "g":
                // TODO recebe
                break;
            default:
                System.out.println("Invalid command specified.");
                break;
        }
        
        socket.close();
    }
    
    private static Boolean fileExistsOnServer(Socket socket, String filePath) {
		return null;
    }
    private static File encryptFileSecret(String filePath, SecretKey key) throws Exception {

	    Cipher c = Cipher.getInstance("AES");
	    c.init(Cipher.ENCRYPT_MODE, key);

    	FileInputStream fis = new FileInputStream(filePath);
	    FileOutputStream fos = new FileOutputStream(filePath+".cifrado");

	    CipherOutputStream cos = new CipherOutputStream(fos, c);
	    byte[] b = new byte[16];  
	    int i = fis.read(b);
	    while (i != -1) {
	        cos.write(b, 0, i);
	        i = fis.read(b);
	    }
	    cos.close();
	    fis.close();
        File file = new File(filePath);
    	return file;
    }

    private static File encryptKeyFile(SecretKey secretKey, PublicKey publicKey, String filePath) throws Exception {
        Cipher cRSA = Cipher.getInstance("RSA");
        cRSA.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedSecretKey = cRSA.wrap(secretKey);
        
        //saves encrypted key on a file
        FileOutputStream keyOutFile = new FileOutputStream(filePath + ".chave_secreta");
        keyOutFile.write(encryptedSecretKey);
        keyOutFile.close();
        File file = new File(filePath);
    	return file;
    }

    private static void sendFile(Socket socket, File file) throws Exception{
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        byte[] buffer = new byte[(int) file.length()];
        FileInputStream fis = new FileInputStream(file);
        fis.read(buffer);
        fis.close();
        out.writeObject(buffer);
        System.out.println("Sent file: " + file);
    }

    private static void sendEncryptedFile(Socket socket, List<String> filePaths) throws Exception {
    	for (String filePath : filePaths) {
    		// Check if the encrypted file already exists on the server
            if (fileExistsOnServer(socket, filePath)) {
                System.err.println("Encrypted file already exists on server: " + filePath);
                continue;
            }
            //gerar secretKey
            KeyGenerator kg = KeyGenerator.getInstance("AES");
	        kg.init(128);
	        SecretKey secretKey = kg.generateKey();

	        //get privateKey from keystore
	        FileInputStream kfile = new FileInputStream("keystore.maria");  //keystore
	        KeyStore kstore = KeyStore.getInstance("PKCS12");
	        kstore.load(kfile, "123456".toCharArray());           //password
	        Certificate cert = kstore.getCertificate("maria");    //alias do utilizador
	        PublicKey publicKey = cert.getPublicKey();

            //cifra ficheiro com chave simetrica
            File encryptedFile = encryptFileSecret(filePath, secretKey);
            //cifra chave simetrica com a chaver privada
            File encryptedKey = encryptKeyFile(secretKey, publicKey, filePath);

            //envia ficheiro cifrado ao servidor
            sendFile(socket, encryptedFile);
            //envia  chave simetrica cifrada ao servidor
            sendFile(socket, encryptedKey);

    	}
    }
}