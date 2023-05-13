package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Command {
    private static String alias;
    private static Certificate cert;
    private static KeyStore kstore;
    private String password;
    private String username;
    private static boolean e_option = false;

    private static DataOutputStream dataOutputStream;
    private static DataInputStream dataInputStream;


    public Command(Socket socket, String username,
                   String password) throws Exception {
        dataOutputStream = new DataOutputStream(socket.getOutputStream());
        dataInputStream = new DataInputStream(socket.getInputStream());

        this.password = password;
        this.username = username;
    }

    private void loadKeyStore() throws Exception{
        FileInputStream kfile = new FileInputStream("certificates/" + username + ".keystore");
        try{
            kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile, password.toCharArray()); // senha
        } catch (Exception e) {
            System.out.println("Keystore's password is incorrect.");
            System.exit(-1);
        }
        alias = kstore.aliases().nextElement();
        cert = kstore.getCertificate(alias);
    }

    private static boolean verifyUserCredentials(String username,
                                                 String password) throws Exception {
        dataOutputStream.writeUTF(username);
        dataOutputStream.writeUTF(password);
        System.out.println("logging in as " + username);

        return dataInputStream.readBoolean();
    }

    public void c(String recipient, List<String> filenames) throws Exception{

        dataOutputStream.writeInt(0); //send command
        if(!verifyUserCredentials(username, password)){
            System.out.println("Username or password are incorrect");
            return;
        }
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*2);
        
        loadKeyStore();

        String extension = getFileExtension(recipient);
        handleCertificates(recipient);

        PublicKey publicKey = cert.getPublicKey();

        for (String filePath : filenames) {
            File file = new File(filePath);
            if (file.exists()){

                //gerar secretKey
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey secretKey = kg.generateKey();
                
                //cifra ficheiro com chave simetrica
                File encryptedFile = encryptFileSecret(file, secretKey, extension);
                //cifra chave simetrica com a chaver privada
                File encryptedKey = encryptKeyFile(file, secretKey, publicKey, extension);

                //envia ficheiro cifrado para o servidor
                sendFileIfNotExistsOnServer(encryptedFile);
                //envia a chave secreta para o servidor
                sendFileIfNotExistsOnServer(encryptedKey);

            } else {
                System.out.println("The file \"" + filePath +
                                   "\" doesn't exist locally.");
            }
        }
    }

    public void s(String recipient, List<String> filenames) throws Exception{
        // Chave privada do assinante -> keystore
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());

        dataOutputStream.writeInt(0); // send command
        if(!verifyUserCredentials(username, password)){
            System.out.println("Username or password are incorrect");
            return;
        }
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*2);

        String extension = getFileExtension(recipient);
        handleCertificates(recipient);

        for (String filePath : filenames) {
            File file = new File(filePath);
            if (file.exists()){
                List<File> files = signFile(file, privateKey, extension);

                //envia o ficheiro assinado para o servidor
                sendFileIfNotExistsOnServer(files.get(0));
                //envia a assinatura para o servidor
                sendFileIfNotExistsOnServer(files.get(1));

            } else {
                System.out.println("The file \"" + filePath +
                                   "\" doesnt's exist locally.");
            }
        }
    }
    
    public void e(String recipient, List<String> filenames) throws Exception{
        e_option = true;
        dataOutputStream.writeInt(0); // send command
        if(!verifyUserCredentials(username, password)){
            System.out.println("Username or password are incorrect");
            return;
        }
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*3);


        // Chave privada do assinante -> keystore
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());

        String extension = getFileExtension(recipient);
        handleCertificates(recipient);
            
        PublicKey publicKey = cert.getPublicKey();

        for (String filePath : filenames) {
            File file = new File(filePath);
            if (file.exists()){
                
                //gerar secretKey
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey secretKey = kg.generateKey();
                
                List<File> files = signFile(file, privateKey, extension);
                
                //cifra ficheiro com chave simetrica
                File securedFile = encryptFileSecret(files.get(0), secretKey, extension);
                //cifra chave simetrica com a chaver privada
                File encryptedKey = encryptKeyFile(files.get(0), secretKey, publicKey, extension);
                
                //envia o ficheiro seguro para o servidor
                sendFileIfNotExistsOnServer(securedFile);
                //envia a assinatura para o servidor
                sendFileIfNotExistsOnServer(files.get(1));
                //envia a chave secreta para o servidor
                sendFileIfNotExistsOnServer(encryptedKey);
                
            } else {
                System.out.println("The file \"" + filePath +
                                   "\" doesnt's exist locally.");
            }
        }
    }

    public void g(String recipient, List<String> filenames) throws Exception{
        //obter chave privada
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());
        
        dataOutputStream.writeInt(1); //send command
        if(!verifyUserCredentials(username, password)){
            System.out.println("Username or password are incorrect");
            return;
        }
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(filenames.size());
        
        for (String filePath : filenames) {
            List<String> serverFiles = new ArrayList<String>();
            
            String extension = "";
            dataOutputStream.writeUTF(filePath);
            
            if (dataInputStream.readBoolean()){
                System.out.println("File doesn't exist on server");
            } else {
                extension = dataInputStream.readUTF();

                if (!(extension.equals(""))){
                    handleCertificates(extension);

                    privateKey =
                        (PrivateKey) kstore.getKey(alias, password.toCharArray());
                    extension = "." + extension;
                } else {
                    dataOutputStream.writeBoolean(false);
                }

                int n_files = dataInputStream.readInt();
                
                for (int i = 0; i < n_files; i++){
                    //read utf
                    String filename = dataInputStream.readUTF();
                    serverFiles.add(filename);

                    receiveFile(filename);
                }
            }
            
            decryptReceivedFile(serverFiles, filePath, cert, privateKey, extension);
            for (String file : serverFiles){
                File file2 = new File(file);
                file2.delete();
            }
        }
    }

    public void au(String username, String password,
                   String certificate) throws Exception {
        dataOutputStream.writeInt(2); //user creation command
        dataOutputStream.writeUTF(username);
        dataOutputStream.writeUTF(password);

        File certFile = new File(certificate);
        sendFile(certFile);

        if(dataInputStream.readBoolean()){
            System.out.println("User " + username + " created successfully.");
        }else{
            System.out.println("Error: User" + username + "already exists.");
        }
    }

    private String getFileExtension(String recipient) {
        if (!username.equals(recipient)) {
            return "." + username;
        }
        return "";
    }

    private void handleCertificates(String recipient) throws Exception{
        if (!username.equals(recipient)){
            File certFile = new File("certificates/" + recipient + ".cer");
            
            if (!certFile.exists()){
                dataOutputStream.writeBoolean(true);
                if (!dataInputStream.readBoolean()){ //check if certificate exists on server
                    System.out.println("Certificate of " + recipient +
                                       " can't be found locally or in the server");
                    System.exit(-1);
                } else {
                    certFile = new File("certificates/" + dataInputStream.readUTF());
                    receiveFile("certificates/" + certFile.getName());
                }
            } else {
                dataOutputStream.writeBoolean(false);
            }
            FileInputStream certFileStream = new FileInputStream(certFile);
            
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                cert = cf.generateCertificate(certFileStream);
            } catch (Exception e) {
                System.out.println("Failed to load certificate.");
                System.exit(-1);
            }

        } else {
            dataOutputStream.writeBoolean(false);
        }
    }

    private static void decryptReceivedFile(List<String> serverFiles,
                                            String filePath, Certificate cert,
                                            PrivateKey privateKey, String extension) throws Exception {
        if (serverFiles.contains(filePath + ".cifrado" + extension)
            && serverFiles.contains(filePath + ".chave_secreta" + extension)){

            File encryptedFile = new File(filePath + ".cifrado" + extension);
            File encryptedKey = new File(filePath + ".chave_secreta" + extension);

    		decryptFile(encryptedFile, encryptedKey, privateKey, filePath);

        } else if (serverFiles.contains(filePath + ".assinado" + extension)
                   && serverFiles.contains(filePath + ".assinatura" + extension)){
            
            File signedFile = new File(filePath + ".assinado" + extension);
            File signatureFile = new File(filePath + ".assinatura" + extension);

            Files.copy(signedFile.toPath(), Paths.get(filePath));

            boolean signatureStatus =
                verifySignature(signedFile.getName(), signatureFile.getName(), cert);
            if(signatureStatus) {
                System.out.println(filePath + " verificado");
            } else {
                System.err.println(filePath +
                                   " não passa a verificação da assinatura");
            }

        } else if (serverFiles.contains(filePath + ".seguro" + extension)
                   && serverFiles.contains(filePath + ".seguro.assinatura" + extension)
                   && serverFiles.contains(filePath + ".seguro.chave_secreta" + extension)){
            
            File encryptedFile = new File(filePath + ".seguro" + extension);
            File encryptedKey = new File(filePath + ".seguro.chave_secreta" + extension);

            decryptFile(encryptedFile, encryptedKey, privateKey, filePath);

	        boolean signatureStatus = verifySignature(filePath,
                                    filePath + ".seguro.assinatura" + extension, cert);
	        if(signatureStatus) {
				System.out.println(filePath + " verificado");
	        } else {
				System.err.println(filePath +
                                   " não passa a verificação da assinatura");
	        }
        }
    }

    private static void receiveFile(String filename) throws Exception{
        int bytes = 0;
        
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

    private static List<File> signFile (File file, PrivateKey privateKey,
                                        String extension) throws Exception{
            List<File> files = new ArrayList<File>();

            File signedFile = null;
            File signatureFile = null;
    
            if (e_option){
                signedFile = new File(file.getName());
                signatureFile = new File(file.getName() + ".seguro" + ".assinatura" + extension);
            } else {
                signedFile = new File(file.getName() + ".assinado" + extension);
                signatureFile = new File(file.getName() + ".assinatura" + extension);
            }
            
    
            Files.copy(file.toPath(), signedFile.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
    
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
    
            FileInputStream fileInputStream= new FileInputStream(file);
            byte[] buffer = new byte[1024];
            int n;
            while ((n = fileInputStream.read(buffer)) != -1) {
                signature.update(buffer, 0, n);
            }
            fileInputStream.close();
    
            FileOutputStream fileOutputStream = new FileOutputStream(signatureFile);
            fileOutputStream.write(signature.sign());
            fileOutputStream.close();
    
            files.add(signedFile);
            files.add(signatureFile);
    
            return files;
    }

    private static int numberValidFiles(List<String> filenames){
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

    private static File encryptFileSecret(File file, SecretKey key,
                                          String extension) throws Exception {
	    Cipher c = Cipher.getInstance("AES");
	    c.init(Cipher.ENCRYPT_MODE, key);

    	FileInputStream fis = new FileInputStream(file);
	    FileOutputStream fos = null;
        File encryptedFile = null;

        if (e_option){
            fos = new FileOutputStream(file.getName() + ".seguro" + extension);
        } else {
            fos = new FileOutputStream(file.getName() + ".cifrado" + extension);
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
        
        if (e_option){
            encryptedFile = new File(file.getName() + ".seguro" + extension);;
        } else {
            encryptedFile = new File(file.getName() + ".cifrado" + extension);
        }
        
        return encryptedFile;
    }

    private static void decryptFile(File encryptedFile, File encryptedKey,
                                    PrivateKey privateKey, String filePath) throws Exception{
        FileInputStream fisEncryptedKey = new FileInputStream(encryptedKey);
        byte[] encryptedKeyBytes = new byte[fisEncryptedKey.available()];
        fisEncryptedKey.read(encryptedKeyBytes);

        Cipher c2 = Cipher.getInstance("RSA");
        c2.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey secretKey = (SecretKey) c2.unwrap(encryptedKeyBytes,
                                                    "AES", Cipher.SECRET_KEY);
        fisEncryptedKey.close();

        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, secretKey);

        FileInputStream fisEncryptedFile = new FileInputStream(encryptedFile);
        CipherInputStream cis = new CipherInputStream(fisEncryptedFile, c);

        FileOutputStream fos = new FileOutputStream(filePath);

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

    private static File encryptKeyFile(File file, SecretKey secretKey,
                                       PublicKey publicKey, String extension) throws Exception {
        Cipher cRSA = Cipher.getInstance("RSA");
        cRSA.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedSecretKey = cRSA.wrap(secretKey);
        
        //saves encrypted key on a file
        FileOutputStream keyOutFile = null;
        if (e_option){
            keyOutFile = new FileOutputStream(file.getName() + ".seguro" + ".chave_secreta" + extension);
        } else {
            keyOutFile = new FileOutputStream(file.getName() + ".chave_secreta" + extension);
        }
        
        keyOutFile.write(encryptedSecretKey);
        keyOutFile.close();
        File keyFile = null;
        if (e_option) {
            keyFile = new File(file.getName() + ".seguro" + ".chave_secreta" + extension);
        } else {
            keyFile = new File(file.getName() + ".chave_secreta" + extension);
        }
    	return keyFile;
    }

    public void sendFileIfNotExistsOnServer(File file) throws Exception {
        if (!existsOnServer(file)) {
            sendFile(file);
            file.delete();
        } else {
            file.delete();
            System.out.println("The file \"" + file.getName().replaceAll("\\.(seguro|cifrado|assinatura|assinado|chave_secreta)$", "") + "\" already exists on server.");
        }
    }

    private static boolean existsOnServer(File file) throws Exception {
        dataOutputStream.writeUTF(file.getName());
        return dataInputStream.readBoolean();
    }

    private static void sendFile(File file) throws Exception{
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

    private static boolean verifySignature(String filePath, String signaturePath,
                                           Certificate cert) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(filePath);
        
        byte [] buffer = new byte [16];
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(cert);
        
        int n;
        while((n = fileInputStream.read(buffer))!= -1) {
        	s.update(buffer,0,n);
        }
        
        byte [] signature = new byte [256];
        FileInputStream fileSignature = new FileInputStream(signaturePath);
        fileSignature.read(signature);
        boolean boolSignature = s.verify(signature);
        
        fileSignature.close();
        fileInputStream.close();

        return (boolSignature);
    }
}
