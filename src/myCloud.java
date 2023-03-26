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
import javax.crypto.SecretKey;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import java.io.ObjectInputStream;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.io.FileInputStream;  	
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.File;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class myCloud {

    private static ArrayList<String> filenames;
    private static String mode = "";

    public static void main(String[] args) throws Exception {
        String address = "localhost";
        int port = 9999;
        filenames = new ArrayList<String>();

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
            	sendEncryptedFile(socket, filenames);
                break;
            case "s":
                if (filenames.isEmpty()) {
                    System.out.println("No files provided.");
                    return;
                }
                assina(socket, filenames);
                break;
            case "e":
                assina_cifra(socket, filenames);
                break;
            case "g":
                // TODO recebe
            	receibeFile(socket, filenames);
                break;
            default:
                System.out.println("Invalid command specified.");
                break;
        }
        
        socket.close();
    }
    
    private static File encryptFileSecret(String filePath, SecretKey key) throws Exception {
	    Cipher c = Cipher.getInstance("AES");
	    c.init(Cipher.ENCRYPT_MODE, key);

    	FileInputStream fis = new FileInputStream(filePath);
	    FileOutputStream fos = null;
        File file = null;

        if (mode.charAt(0) == 'c'){
            fos = new FileOutputStream(filePath + ".cifrado");
        } else if (mode.charAt(0) == 'e'){
            fos = new FileOutputStream(filePath);
        }

	    CipherOutputStream cos = new CipherOutputStream(fos, c);
	    byte[] b = new byte[16];  
	    int i = fis.read(b);
	    while (i != -1) {
	        cos.write(b, 0, i);
	        i = fis.read(b);
	    }
	    cos.close();
	    fis.close();
        
        if (mode.charAt(0) == 'c'){
            file = new File(filePath + ".cifrado");
        } else if (mode.charAt(0) == 'e'){
            file = new File(filePath);
        }
        
        return file;
    }

    private static String decryptFileSecret(String filePath, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(filePath);
        CipherInputStream cis = new CipherInputStream(fis, c);

        String decryptedFilePath = filePath.substring(0, filePath.lastIndexOf("."));
        FileOutputStream fos = new FileOutputStream(decryptedFilePath);

        byte[] b = new byte[256];
        int i = cis.read(b);
        while (i != -1) {
            fos.write(b, 0, i);
            i = cis.read(b);
        }

        fos.close();
        cis.close();
        fis.close();

        return decryptedFilePath;
    }

    private static File encryptKeyFile(SecretKey secretKey, PublicKey publicKey, String filePath) throws Exception {
        Cipher cRSA = Cipher.getInstance("RSA");
        cRSA.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedSecretKey = cRSA.wrap(secretKey);
        
        //saves encrypted key on a file
        FileOutputStream keyOutFile = new FileOutputStream(filePath + ".chave_secreta");
        keyOutFile.write(encryptedSecretKey);
        keyOutFile.close();
        File file = new File(filePath + ".chave_secreta");
    	return file;
    }

    private static SecretKey decryptKeyFile(String keyPath, Key privateKey) throws Exception {
        FileInputStream encryptedKey = new FileInputStream(keyPath);
        byte[] encryptedKeyBytes = new byte[encryptedKey.available()];
        encryptedKey.read(encryptedKeyBytes);

        Cipher c2 = Cipher.getInstance("RSA");
        c2.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey secretKey = (SecretKey) c2.unwrap(encryptedKeyBytes, "AES", Cipher.SECRET_KEY);
 
        encryptedKey.close();
    	return secretKey;
    }

    private static boolean sendFile(Socket socket, File file, DataOutputStream dataOutputStream, DataInputStream dataInputStream) throws Exception{
        int bytes = 0;
        boolean doesntExist = true;
        
        FileInputStream fileInputStream = new FileInputStream(file); 

        dataOutputStream.writeUTF(file.getName());

        if(!dataInputStream.readBoolean()) {
        	doesntExist = false;
        } else {
        	dataOutputStream.writeLong(file.length());
        	byte[] buffer = new byte[1024];
        	while ((bytes = fileInputStream.read(buffer)) != -1) {
        	    dataOutputStream.write(buffer, 0, bytes);
        	    dataOutputStream.flush();
        	}

        	System.out.println("Sent file: " + file);
        }

        fileInputStream.close();
        return doesntExist;
    }

    private static boolean getFile(Socket socket, String filePath, DataOutputStream dataOutputStream, DataInputStream dataInputStream) throws Exception{
    	int bytes = 0;
        boolean exist = true;

		System.out.println("Requesting file: " + filePath);
        dataOutputStream.writeUTF(filePath);

        if(!(Boolean)dataInputStream.readBoolean()) {
        	exist = false;
        } else {
        	FileOutputStream fileOutputStream = new FileOutputStream(filePath);

        	long size = dataInputStream.readLong();

		    byte[] buffer = new byte[1024];
			while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
				fileOutputStream.write(buffer, 0, bytes);
				size -= bytes;
			}

			System.out.println("Received file: " + filePath);
			fileOutputStream.close();
        }
    	return exist;
    }

    private static void sendEncryptedFile(Socket socket, List<String> filePaths) throws Exception {
        OutputStream outputStream = socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

        dataOutputStream.writeInt(0); //send command
        dataOutputStream.writeInt(filenames.size()*2);
        
    	for (String filePath : filePaths) {
            //gerar secretKey
            KeyGenerator kg = KeyGenerator.getInstance("AES");
	        kg.init(128);
	        SecretKey secretKey = kg.generateKey();

	        //get privateKey from keystore
	        FileInputStream kfile = new FileInputStream("keystore.maria");  //keystore
	        KeyStore kstore = KeyStore.getInstance("PKCS12");
	        kstore.load(kfile, "123123".toCharArray());           //password
	        Certificate cert = kstore.getCertificate("maria");    //alias do utilizador
	        PublicKey publicKey = cert.getPublicKey();

            //cifra ficheiro com chave simetrica
            File encryptedFile = encryptFileSecret(filePath, secretKey);
            //cifra chave simetrica com a chaver privada
            File encryptedKey = encryptKeyFile(secretKey, publicKey, filePath);

            //envia ficheiro cifrado ao servidor
            if (!sendFile(socket, encryptedFile, dataOutputStream, dataInputStream)) {
                System.err.println("File already exists on server: " + encryptedFile);
            }
            //envia  chave simetrica cifrada ao servidor
            if (!sendFile(socket, encryptedKey, dataOutputStream, dataInputStream)) {
                System.err.println("File already exists on server: " + encryptedKey);
            }
            
    	}
    }

    private static boolean verifySignature(String filePath, String signaturePath, X509Certificate cert) throws Exception{
        FileInputStream file = new FileInputStream(filePath);
        
        byte [] buffer = new byte [16];
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(cert);
        
        int n;
        while((n = file.read(buffer))!= -1) {
        	s.update(buffer,0,n);
        }
        
        byte [] signature = new byte [256];
        FileInputStream fileSignature = new FileInputStream(signaturePath);
        fileSignature.read(signature);
        boolean boolSignature = s.verify(signature);
        
        fileSignature.close();
        file.close();

        return (boolSignature);
    }

    private static void receibeFile(Socket socket, List<String> filePaths) throws Exception {
        OutputStream outputStream = socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

    	FileInputStream kfile2 = new FileInputStream("keystore.maria"); // keystore
    	KeyStore kstore = KeyStore.getInstance("PKCS12");
    	kstore.load(kfile2, "123123".toCharArray()); // password

        dataOutputStream.writeInt(1); //send command
        
    	for (String filePath : filePaths) {
    		if (filePath.endsWith(".cifrado")) {
    			dataOutputStream.writeInt(filenames.size()*2);
    			if (!getFile(socket, filePath, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + filePath);
    			}
    			String fileKey = filePath.substring(0, filePath.lastIndexOf(".")) + ".chave_secreta";
    			if (!getFile(socket, fileKey, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + fileKey);
    			}

    			//obter chave privada
    			Key privateKey = kstore.getKey("maria", "123123".toCharArray());

    			//obter chave simetrica
    			SecretKey secretKey = decryptKeyFile(fileKey, privateKey);

    			//decifrar ficheiro
    			decryptFileSecret(filePath, secretKey);

    		} else if (filePath.endsWith(".assinado")) {
    			dataOutputStream.writeInt(filenames.size()*2);
    			if (!getFile(socket, filePath, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + filePath);
    			}
    			String signaturePath = filePath.substring(0, filePath.lastIndexOf(".")) + ".assinatura";
    			if (!getFile(socket, signaturePath, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + signaturePath);
    			}
    			// obter certificado do assinante
    		    X509Certificate cert = (X509Certificate) kstore.getCertificate("maria");
    	        
    	        boolean signatureStatus = verifySignature(filePath, signaturePath, cert);
    	        if(signatureStatus) {
    				System.out.println(filePath + " verificado");
    	        } else {
    				System.err.println(filePath + " não passa a verificação da assinatura");
    	        }
    	        
    		} else if (filePath.endsWith(".seguro")) {
    			dataOutputStream.writeInt(filenames.size()*3);
    			if (!getFile(socket, filePath, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + filePath);
    			}
    			String fileKey = filePath + ".chave_secreta";
    			if (!getFile(socket, fileKey, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + fileKey);
    			}
    			String signaturePath = filePath.substring(0, filePath.lastIndexOf(".")) + ".assinatura";
    			if (!getFile(socket, signaturePath, dataOutputStream, dataInputStream)) {
    				System.err.println("File doesn't exists on server: " + signaturePath);
    			}

    			//obter chave privada
    			Key privateKey = kstore.getKey("maria", "123123".toCharArray());

    			//obter chave simetrica
    			SecretKey secretKey = decryptKeyFile(fileKey, privateKey);

    			//decifrar ficheiro
    			String decryptedFilePath = decryptFileSecret(filePath, secretKey);

    			// obter certificado do assinante
    		    X509Certificate cert = (X509Certificate) kstore.getCertificate("maria");
    	        
    	        boolean signatureStatus = verifySignature(decryptedFilePath, signaturePath, cert);
    	        if(signatureStatus) {
    				System.out.println(filePath + " verificado");
    	        } else {
    				System.err.println(filePath + " não passa a verificação da assinatura");
    	        }
    		} else {
    			System.err.println("File doesn't exists on server: " + filePath);
    		}
    	}
    }

    private static void assina_cifra(Socket socket, List<String> filePaths) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
	    kg.init(128);
        SecretKey secretKey = kg.generateKey();

        //get privateKey from keystore
        FileInputStream kfile = new FileInputStream("keystore.maria");  //keystore
        KeyStore kstore = KeyStore.getInstance("PKCS12");
        kstore.load(kfile, "123123".toCharArray());           //password
        Certificate cert = kstore.getCertificate("maria");    //alias do utilizador
        PublicKey publicKey = cert.getPublicKey();
	    Key minhaChavePrivada = kstore.getKey("maria", "123123".toCharArray());

        OutputStream outputStream = socket.getOutputStream();
	    DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
	    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

		dataOutputStream.writeInt(0); // send command
		dataOutputStream.writeInt(filenames.size()*3);

        for (String filePath : filePaths) {
            File file = new File(filePath);
            File signatureFile = new File(filePath + ".assinatura");
            File securedFile = new File(filePath + ".seguro");
            

            Signature signature = Signature.getInstance("SHA256withRSA");
	        signature.initSign((PrivateKey) minhaChavePrivada);

	        FileInputStream fis = new FileInputStream(file);
	        byte[] buffer = new byte[1024];
	        int n;
	        while ((n = fis.read(buffer)) != -1) {
	            signature.update(buffer, 0, n);
	        }
	        fis.close();

            // Escreve o arquivo assinado
	        FileOutputStream fos = new FileOutputStream(securedFile);
	        fos.write(signature.sign());
	        fos.close();

	        // Cria o arquivo de assinatura localmente
	        signatureFile.createNewFile();

	        // Escreve o arquivo de assinatura
	        fos = new FileOutputStream(signatureFile);
	        fos.write(signature.sign());
	        fos.close();

            //cifra ficheiro com chave simetrica
            securedFile = encryptFileSecret(securedFile.getName(), secretKey);
            //cifra chave simetrica com a chaver privada
            File encryptedKey = encryptKeyFile(secretKey, publicKey, securedFile.getName());

            if (!sendFile(socket, signatureFile, dataOutputStream, dataInputStream)) {
                System.err.println("File already exists on server: " + signatureFile);
            }
            //envia  chave simetrica cifrada ao servidor
            if (!sendFile(socket, encryptedKey, dataOutputStream, dataInputStream)) {
                System.err.println("File already exists on server: " + encryptedKey);
            }
            if (!sendFile(socket, securedFile, dataOutputStream, dataInputStream)) {
                System.err.println("File already exists on server: " + securedFile);
            }
        }
    }

    private static void assina(Socket socket, List<String> filePaths) throws Exception {

        OutputStream outputStream = socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        DataInputStream inputStream = new DataInputStream(socket.getInputStream());

        // Chave privada do assinante -> keystore
        FileInputStream kfile2 = new FileInputStream("keystore.maria"); // keystore
        KeyStore kstore = KeyStore.getInstance("PKCS12");
        kstore.load(kfile2, "123123".toCharArray()); // senha
        Key minhaChavePrivada = kstore.getKey("maria", "123123".toCharArray());

        dataOutputStream.writeInt(0); // send command
        dataOutputStream.writeInt(filePaths.size()*2);

        // Itera por cada ficheiro
        for (String filePath : filePaths) {

            // Verifica se o arquivo existe localmente
            File arquivo = new File(filePath);
            if (!arquivo.exists()) {
                System.err.println("O ficheiro nao existe: " + filePath);
                continue;
            }

            // Verifica se o arquivo de assinatura já existe localmente
            String signatureFilePath = filePath + ".assinatura";
            File signatureFile = new File(signatureFilePath);
            if (signatureFile.exists()) {
                System.err.println("Signature file already exists: " + signatureFilePath);
                continue;
            }

            // Cria o arquivo assinado localmente
            String signedFilePath = filePath + ".assinado";
            File signedFile = new File(signedFilePath);
            signedFile.createNewFile();

            // Faz a cópia do arquivo original para o arquivo assinado
            Files.copy(arquivo.toPath(), signedFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

            // Assina o arquivo
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign((PrivateKey) minhaChavePrivada);

            FileInputStream fis = new FileInputStream(signedFile);
            byte[] buffer = new byte[1024];
            int n;
            while ((n = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, n);
            }
            fis.close();

            // Escreve o arquivo de assinatura
            FileOutputStream fos = new FileOutputStream(signatureFilePath);
            fos.write(signature.sign());
            fos.close();

            File signatureFileToSend = new File(signatureFilePath);

            // Envia o arquivo assinado para o servidor
            if (!sendFile(socket, signedFile, dataOutputStream, inputStream)) {
                System.err.println("File already exists on server: " + signedFile);
            }
            // Envia o arquivo de assinatura para o servidor
            if (!sendFile(socket, signatureFileToSend, dataOutputStream, inputStream)) {
                System.err.println("File already exists on server: " + signatureFileToSend);
            }
        }
    }
}
