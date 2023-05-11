package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
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
        try (BufferedReader reader = new BufferedReader(new FileReader("users"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(";");
                if (parts[0].equals(username)) {
                    byte[] salt = Base64.getDecoder().decode(parts[2]);
                    String storedHash = parts[1];
                    String computedHash = hashPassword(password, salt);
                    return storedHash.equals(computedHash);
                }
            }
        }
        return false;
    }

    public void c(String recipient, List<String> filenames) throws Exception{
        if(!verifyUserCredentials(username, password)){
            System.out.println("username or pasword are incorrect");
            return;
        }

        dataOutputStream.writeInt(0); //send command
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*2);
        
        String extension = getFileExtension(recipient);
        handleCertificates(recipient, extension);

        //get privateKey
        loadKeyStore();
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
        if(!verifyUserCredentials(username, password)){
            System.out.println("username or pasword are incorrect");
            return;
        }

        // Chave privada do assinante -> keystore
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());

        dataOutputStream.writeInt(0); // send command
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*2);

        String extension = getFileExtension(recipient);
        handleCertificates(recipient, extension);

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
        if(!verifyUserCredentials(username, password)){
            System.out.println("username or pasword are incorrect");
            return;
        }
        e_option = true;
        dataOutputStream.writeInt(0); // send command
        dataOutputStream.writeUTF(recipient);
        dataOutputStream.writeInt(numberValidFiles(filenames)*3);

        String extension = getFileExtension(recipient);
        handleCertificates(recipient, extension);

        // Chave privada do assinante -> keystore
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());
            
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

    public void g(List<String> filenames) throws Exception{
        if(!verifyUserCredentials(username, password)){
            System.out.println("username or pasword are incorrect");
            return;
        }
        //obter chave privada
        loadKeyStore();
        PrivateKey privateKey =
            (PrivateKey) kstore.getKey(alias, password.toCharArray());
        
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
                    //read utf
                    String filename = dataInputStream.readUTF();
                    serverFiles.add(filename);
                    
                    receiveFile(filename);
                }
            }
            
            decryptReceivedFile(serverFiles, filePath, cert2, privateKey);
        }
    }

    public void au(String username, String password,
                   String certificate) throws Exception {
        if(verifyUserCredentials(username, password)){
            System.out.println("User already exists");
            return;
        }

        byte[] salt = createSalt();
        String passwordHash = hashPassword(password, salt);
        
        // Append to the users file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("users", true))) {
            writer.write(username + ";" + passwordHash + ";" +
                         Base64.getEncoder().encodeToString(salt));
            writer.newLine();
        }


        // TODO send certificate to server
    }

    private static byte[] createSalt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static String hashPassword(String password, byte[] salt) throws Exception{
        String passwordHash = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] bytes = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        passwordHash = sb.toString();
        return passwordHash;
    }

    public static boolean verifyPassword(String hash, byte[] salt,
                                         String password) throws Exception {
        String computedHash = hashPassword(password, salt);
        return hash.equals(computedHash);
    }

    private String getFileExtension(String recipient) {
        if (!username.equals(recipient)) {
            return "." + username;
        }
        return "";
    }

    private void handleCertificates(String recipient, String extension) throws Exception{
        if (!username.equals(recipient)){
            File certFile = new File("certificates/" + recipient + ".keystore");
            
            if (!certFile.exists()){
                dataOutputStream.writeBoolean(true);
                if (!dataInputStream.readBoolean()){ //check if certificate exists on server
                    System.out.println("Certificate of " + recipient +
                                       " can't be found locally or in the server");
                    System.exit(-1);
                } else {
                    receiveFile("certificates/" + certFile.getName());
                }
            } else {
                dataOutputStream.writeBoolean(false);
            }
            
            FileInputStream kfile = new FileInputStream(certFile);
            
            try{
                kstore = KeyStore.getInstance("PKCS12");
                kstore.load(kfile, password.toCharArray()); // senha
            } catch (Exception e) {
                System.out.println("Keystore's password is incorrect.");
                System.exit(-1);
            }
            
            alias = kstore.aliases().nextElement();
            cert = kstore.getCertificate(alias);
        } else {
            dataOutputStream.writeBoolean(false);
        }
        
    }

    private static void decryptReceivedFile(List<String> serverFiles,
                                            String filePath, X509Certificate cert,
                                            PrivateKey privateKey) throws Exception {
        if (serverFiles.contains(filePath + ".cifrado")
            && serverFiles.contains(filePath + ".chave_secreta")){

            File encryptedFile = new File(serverFiles.get(0));
            File encryptedKey = new File(serverFiles.get(1));

    		decryptFile(encryptedFile, encryptedKey, privateKey);

        } else if (serverFiles.contains(filePath + ".assinado")
                   && serverFiles.contains(filePath + ".assinatura")){
            boolean signatureStatus =
                verifySignature(serverFiles.get(0), serverFiles.get(1), cert);
            if(signatureStatus) {
                System.out.println(filePath + " verificado");
            } else {
                System.err.println(filePath +
                                   " não passa a verificação da assinatura");
            }

        } else if (serverFiles.contains(filePath + ".seguro")
                   && serverFiles.contains(filePath + ".seguro.assinatura")
                   && serverFiles.contains(filePath + ".seguro.chave_secreta")){
            File encryptedFile = new File(serverFiles.get(0));
            File encryptedKey = new File(serverFiles.get(2));

            decryptFile(encryptedFile, encryptedKey, privateKey);

	        boolean signatureStatus = verifySignature(filePath,
                                                      serverFiles.get(1), cert);
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
        File signatureFile = new File(file.getName() + ".assinatura" + extension);

        if (e_option){
            signedFile = new File(file.getName());
        } else {
            signedFile = new File(file.getName() + ".assinado" + extension);
        }
        

        Files.copy(file.toPath(), signedFile.toPath(),
                   StandardCopyOption.REPLACE_EXISTING);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        FileInputStream fileInputStream= new FileInputStream(signedFile);
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
                                    PrivateKey privateKey) throws Exception{
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

        String decryptedFileName = encryptedFile.getName()
            .substring(0, encryptedFile.getName().lastIndexOf("."));
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

    private static File encryptKeyFile(File file, SecretKey secretKey,
                                       PublicKey publicKey, String extension) throws Exception {
        Cipher cRSA = Cipher.getInstance("RSA");
        cRSA.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedSecretKey = cRSA.wrap(secretKey);
        
        //saves encrypted key on a file
        FileOutputStream keyOutFile = new FileOutputStream(file.getName() +
                                                           ".chave_secreta" + extension);
        keyOutFile.write(encryptedSecretKey);
        keyOutFile.close();
        File keyFile = new File(file.getName() + ".chave_secreta" + extension);
    	return keyFile;
    }

    public void sendFileIfNotExistsOnServer(File file) throws Exception {
        if (!existsOnServer(file)) {
            sendFile(file);
            file.delete();
        } else {
            file.delete();
            System.out.println("The file \"" + file.getName() + "\" already exists on server.");
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
                                           X509Certificate cert) throws Exception{
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
