/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/
import java.util.Scanner;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;

import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.io.FileInputStream;  	
import java.io.FileOutputStream;
import java.io.File;

import java.net.Socket;

import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class myCloud {

    private static ArrayList<String> filenames;
    private static String mode;
    private static String alias;
    private static String kstorePassword;

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

        if (filenames.isEmpty()){
            System.out.println("No files provided.");
        } else {
            //connect to socket
            Socket socket = new Socket(address, port);

            OutputStream outputStream = socket.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

            FileInputStream kfile = new FileInputStream("keystore.maria"); // keystore
            
            KeyStore kstore = null;

            Scanner scanner = new Scanner(System.in);  // Create a Scanner object
            System.out.println("Enter keystore password:");
            kstorePassword = scanner.nextLine();  // Read user input
            scanner.close();

            try{
                kstore = KeyStore.getInstance("PKCS12");
                kstore.load(kfile, kstorePassword.toCharArray()); // senha
            } catch (Exception e) {
                System.out.println("Keystore's password is incorrect.");
                System.exit(-1);
            }

            alias = kstore.aliases().nextElement();
            Certificate cert = kstore.getCertificate(alias);

            // Perform action based on command
            switch (mode) {
                case "c": {
                    dataOutputStream.writeInt(0); //send command
                    dataOutputStream.writeInt(numberValidFiles(filenames)*2);

                    //get privateKey
                    PublicKey publicKey = cert.getPublicKey();

                    for (String filePath : filenames) {
                        File file = new File(filePath);
                        if (file.exists()){

                            //gerar secretKey
                            KeyGenerator kg = KeyGenerator.getInstance("AES");
                            kg.init(128);
                            SecretKey secretKey = kg.generateKey();
                
                            //cifra ficheiro com chave simetrica
                            File encryptedFile = encryptFileSecret(file, secretKey, ".cifrado");
                            //cifra chave simetrica com a chaver privada
                            File encryptedKey = encryptKeyFile(file, secretKey, publicKey);

                            //envia ficheiro cifrado para o servidor
                            if(!existsOnServer(encryptedFile, dataOutputStream, dataInputStream)){
                                sendFile(encryptedFile, dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + encryptedFile.getName() + "\" already exists on server.");
                            }

                            //envia a chave secreta para o servidor
                            if(!existsOnServer(encryptedKey, dataOutputStream, dataInputStream)){
                                sendFile(encryptedKey, dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + encryptedKey.getName() + "\" already exists on server.");
                            }

                        } else {
                            System.out.println("The file \"" + filePath + "\" doesn't exist locally.");
                        }
                    }
                }
                    break;
                case "s": {
                    // Chave privada do assinante -> keystore
                    PrivateKey privateKey = (PrivateKey) kstore.getKey(alias, kstorePassword.toCharArray());

                    dataOutputStream.writeInt(0); // send command
                    dataOutputStream.writeInt(numberValidFiles(filenames)*2);

                    for (String filePath : filenames) {
                        File file = new File(filePath);
                        if (file.exists()){
                            List<File> files = signFile(file, privateKey, ".assinado");
                            
                            //envia o ficheiro assinado para o servidor
                            if(!existsOnServer(files.get(0), dataOutputStream, dataInputStream)){
                                sendFile(files.get(0), dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + files.get(0).getName() + "\" already exists on server.");
                            }

                            //envia a assinatura para o servidor
                            if(!existsOnServer(files.get(1), dataOutputStream, dataInputStream)){
                                sendFile(files.get(1), dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + files.get(1).getName() + "\" already exists on server.");
                            }
                        } else {
                            System.out.println("The file \"" + filePath + "\" doesnt's exist locally.");
                        }
                    }
                }
                    break;
                case "e": {
                    // Chave privada do assinante -> keystore
                    PrivateKey privateKey = (PrivateKey) kstore.getKey(alias, kstorePassword.toCharArray());
            
                    PublicKey publicKey = cert.getPublicKey();

                    dataOutputStream.writeInt(0); // send command
                    dataOutputStream.writeInt(numberValidFiles(filenames)*3);

                    for (String filePath : filenames) {
                        File file = new File(filePath);
                        if (file.exists()){

                            //gerar secretKey
                            KeyGenerator kg = KeyGenerator.getInstance("AES");
                            kg.init(128);
                            SecretKey secretKey = kg.generateKey();

                            List<File> files = signFile(file, privateKey, ".seguro");

                            //cifra ficheiro com chave simetrica
                            File securedFile = encryptFileSecret(files.get(0), secretKey, "");
                            //cifra chave simetrica com a chaver privada
                            File encryptedKey = encryptKeyFile(files.get(0), secretKey, publicKey);

                            //envia o ficheiro seguro para o servidor
                            if(!existsOnServer(securedFile, dataOutputStream, dataInputStream)){
                                sendFile(securedFile, dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + securedFile.getName() + "\" already exists on server.");
                            }

                            //envia a assinatura para o servidor
                            if(!existsOnServer(files.get(1), dataOutputStream, dataInputStream)){
                                sendFile(files.get(1), dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + files.get(1).getName() + "\" already exists on server.");
                            }

                            //envia a chave secreta para o servidor
                            if(!existsOnServer(encryptedKey, dataOutputStream, dataInputStream)){
                                sendFile(encryptedKey, dataOutputStream, dataInputStream);
                            } else {
                                System.out.println("The file \"" + encryptedKey.getName() + "\" already exists on server.");
                            }

                        } else {
                            System.out.println("The file \"" + filePath + "\" doesnt's exist locally.");
                        }
                    }
                }
                    break;

                case "g": {
                    
                    //obter chave privada
                    PrivateKey privateKey = (PrivateKey) kstore.getKey(alias, kstorePassword.toCharArray());
                
                    X509Certificate cert2 = (X509Certificate) kstore.getCertificate(alias);
                    
                    dataOutputStream.writeInt(1); //send command
                    dataOutputStream.writeInt(filenames.size());

                    for (String filePath : filenames) {
                        List<String> serverFiles = new ArrayList<String>();

                        dataOutputStream.writeUTF(filePath);

                        if (dataInputStream.readBoolean()){
                            System.out.println("File doesn't exist on server");
                        } else {
                            int n_files = dataInputStream.readInt();

                            for (int i = 0; i < n_files; i++){
                                int bytes = 0;

                                //read utf
                                String filename = dataInputStream.readUTF();
                                serverFiles.add(filename);

                                //read file
                                FileOutputStream fileOutputStream = new FileOutputStream(filename);
                                
                                long size = dataInputStream.readLong();

                                byte[] buffer = new byte[1024];
                                while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
                                    fileOutputStream.write(buffer, 0, bytes);
                                    size -= bytes;
                                }

                                System.out.println("Received file: " + filename);
                                fileOutputStream.close();
                            }
                        }

                        decryptReceivedFile(serverFiles, filePath, cert2, privateKey);

                        
                    }
                }
                    break;
                default:
                    System.out.println("Invalid command specified.");
                    break;
            }       
                socket.close();
        }
    }

    private static void decryptReceivedFile(List<String> serverFiles, String filePath, X509Certificate cert, PrivateKey privateKey) throws Exception {
        if (serverFiles.contains(filePath + ".cifrado") && serverFiles.contains(filePath + ".chave_secreta")){
            File encryptedFile = new File(serverFiles.get(0));
            File encryptedKey = new File(serverFiles.get(1));

    		decryptFile(encryptedFile, encryptedKey, privateKey);

        } else if (serverFiles.contains(filePath + ".assinado") && serverFiles.contains(filePath + ".assinatura")){
            boolean signatureStatus = verifySignature(serverFiles.get(0), serverFiles.get(1), cert);
            if(signatureStatus) {
                System.out.println(filePath + " verificado");
            } else {
                System.err.println(filePath + " não passa a verificação da assinatura");
            }

        } else if (serverFiles.contains(filePath + ".seguro") && serverFiles.contains(filePath + ".seguro.assinatura") && serverFiles.contains(filePath + ".seguro.chave_secreta")){
            File encryptedFile = new File(serverFiles.get(0));
            File encryptedKey = new File(serverFiles.get(2));

            decryptFile(encryptedFile, encryptedKey, privateKey);

	        boolean signatureStatus = verifySignature(filePath, serverFiles.get(1), cert);
	        if(signatureStatus) {
				System.out.println(filePath + " verificado");
	        } else {
				System.err.println(filePath + " não passa a verificação da assinatura");
	        }
        }
    }

    private static List<File> signFile (File file, PrivateKey privateKey, String extension) throws Exception{
        List<File> files = new ArrayList<File>();
        
        File signedFile = new File(file.getName() + extension);
        File signatureFile = null;

        Files.copy(file.toPath(), signedFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        FileInputStream fileInputStream= new FileInputStream(signedFile);
        byte[] buffer = new byte[1024];
        int n;
        while ((n = fileInputStream.read(buffer)) != -1) {
            signature.update(buffer, 0, n);
        }
        fileInputStream.close();
        
        if (extension == ".seguro"){
            signatureFile = new File(file.getName() + extension + ".assinatura");
        } else {
            signatureFile = new File(file.getName() + ".assinatura");
        }

        FileOutputStream fileOutputStream = new FileOutputStream(signatureFile);
        fileOutputStream.write(signature.sign());
        fileOutputStream.close();

        files.add(signedFile);
        files.add(signatureFile);

        return files;
    }

    private static int numberValidFiles(ArrayList<String> filenames){
        int counter = 0;
        File file = null;
        for (String filePath : filenames){
            file = new File(filePath);
            if (file.exists()){
                counter++;
            }
        }
        return counter;
    }

    private static File encryptFileSecret(File file, SecretKey key, String extension) throws Exception {
	    Cipher c = Cipher.getInstance("AES");
	    c.init(Cipher.ENCRYPT_MODE, key);

    	FileInputStream fis = new FileInputStream(file);
	    FileOutputStream fos = null;
        File encryptedFile = null;

        fos = new FileOutputStream(file.getName() + extension);

	    CipherOutputStream cos = new CipherOutputStream(fos, c);
	    byte[] b = new byte[16];  
	    int i = fis.read(b);
	    while (i != -1) {
	        cos.write(b, 0, i);
	        i = fis.read(b);
	    }
	    cos.close();
	    fis.close();
        
        encryptedFile = new File(file.getName() + extension);        
        return encryptedFile;
    }

    private static void decryptFile(File encryptedFile, File encryptedKey, PrivateKey privateKey) throws Exception{
        FileInputStream fisEncryptedKey = new FileInputStream(encryptedKey);
        byte[] encryptedKeyBytes = new byte[fisEncryptedKey.available()];
        fisEncryptedKey.read(encryptedKeyBytes);

        Cipher c2 = Cipher.getInstance("RSA");
        c2.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey secretKey = (SecretKey) c2.unwrap(encryptedKeyBytes, "AES", Cipher.SECRET_KEY);
        fisEncryptedKey.close();

        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, secretKey);

        FileInputStream fisEncryptedFile = new FileInputStream(encryptedFile);
        CipherInputStream cis = new CipherInputStream(fisEncryptedFile, c);

        String decryptedFileName = encryptedFile.getName().substring(0, encryptedFile.getName().lastIndexOf("."));
        FileOutputStream fos = new FileOutputStream(decryptedFileName);

        byte[] b = new byte[256];
        int i = cis.read(b);
        while (i != -1) {
            fos.write(b, 0, i);
            i = cis.read(b);
        }

        fos.close();
        cis.close();
        fisEncryptedFile.close();
    }

    private static File encryptKeyFile(File file, SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cRSA = Cipher.getInstance("RSA");
        cRSA.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedSecretKey = cRSA.wrap(secretKey);
        
        //saves encrypted key on a file
        FileOutputStream keyOutFile = new FileOutputStream(file.getName() + ".chave_secreta");
        keyOutFile.write(encryptedSecretKey);
        keyOutFile.close();
        File keyFile = new File(file.getName() + ".chave_secreta");
    	return keyFile;
    }

    private static boolean existsOnServer(File file, DataOutputStream dataOutputStream, DataInputStream dataInputStream) throws Exception {
        dataOutputStream.writeUTF(file.getName());
        return dataInputStream.readBoolean();
    }

    private static void sendFile(File file, DataOutputStream dataOutputStream, DataInputStream dataInputStream) throws Exception{
        int bytes = 0;
        
        FileInputStream fileInputStream = new FileInputStream(file); 

        dataOutputStream.writeLong(file.length());
        byte[] buffer = new byte[1024];
        while ((bytes = fileInputStream.read(buffer)) != -1) {
            dataOutputStream.write(buffer, 0, bytes);
            dataOutputStream.flush();
        }

        System.out.println("Sent file: " + file);
        

        fileInputStream.close();

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
}