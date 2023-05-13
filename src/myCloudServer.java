/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;


public class myCloudServer {
    private String serverDir = "serverFiles";

	public static void main(String[] args) {
		System.out.println("servidor: main");
		System.setProperty("javax.net.ssl.keyStore", "serverFiles/keystore.server");
		System.setProperty("javax.net.ssl.keyStorePassword", "123123");

		myCloudServer server = new myCloudServer();
		if (args.length == 0) {
            System.out.println("Usage: myCloudServer <serverPort>");
            return;
        }
		server.startServer(Integer.parseInt(args[0]));
	}

	public void startServer (int port){
		ServerSocket sSoc = null;
        
		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
			sSoc = ssf.createServerSocket(port);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
         
		while(true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
		    }
		    catch (IOException e) {
		        e.printStackTrace();
				break;
		    }
		    
		}
		try {
			sSoc.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	//Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}
 
		public void run(){
			try {
				try {
					DataInputStream dataInputStream =
                        new DataInputStream(socket.getInputStream());

					int command = dataInputStream.readInt();
					
					switch (command) {
						case 0: //receive files 
							handleFileReceiving(socket);
							break;
						case 1: //send files 
							handleFileSending(socket);
							break;
						case 2: //create new user
							handleUserCreating(socket);
							break;
					}

				} catch (Exception e) {
					e.printStackTrace();
				}
 			
				socket.close();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private void handleUserCreating(Socket socket) throws Exception {
            DataOutputStream dataOutputStream =
                new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream =
                new DataInputStream(socket.getInputStream());

            String username = dataInputStream.readUTF();
            System.out.println("Creating new user: " + username);
            String password = dataInputStream.readUTF();

            if(verifyUserCredentials(username, password)){
                System.out.println("User " + username + " already exists.");
                dataOutputStream.writeBoolean(false);
            }
            
            byte[] salt = createSalt();
            String passwordHash = hashPassword(password, salt);
            
            File usersFile = new File(serverDir + "/users");
            if (!usersFile.exists()) {
                usersFile.createNewFile();
            }
            // Append to the users file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(usersFile, true))) {
                writer.write(username + ";" + passwordHash + ";" +
                             Base64.getEncoder().encodeToString(salt));
                writer.newLine();
            }
            System.out.println("User " + username + " created.");
            dataOutputStream.writeBoolean(true);
        }

		private void handleUserVerifying(Socket socket) throws Exception {
            DataOutputStream dataOutputStream =
                new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream =
                new DataInputStream(socket.getInputStream());

            String username = dataInputStream.readUTF();
            String password = dataInputStream.readUTF();

            dataOutputStream.writeBoolean(verifyUserCredentials(username, password));
        }

        private boolean verifyUserCredentials(String username, String password) throws Exception {
            File usersFile = new File(serverDir + "/users");
            if (!usersFile.exists()) {
                return false;
            }
            try (BufferedReader reader = new BufferedReader(new FileReader(usersFile))) {
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

        private byte[] createSalt() throws Exception {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            return salt;
        }
        
        private String hashPassword(String password, byte[] salt) throws Exception{
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
        
        public boolean verifyPassword(String hash, byte[] salt,  
                                             String password) throws Exception {
            String computedHash = hashPassword(password, salt);
            return hash.equals(computedHash);
        }
        
		private boolean checkServerFiles(String filePath, String recipient) {
			File[] listFiles = new File(serverDir, recipient).listFiles();

			filePath = filePath.replaceAll("\\.(seguro|cifrado|assinatura|assinado|chave_secreta" + recipient +")$", "");
			for(int i = 0; i < listFiles.length; i++) {
				if (listFiles[i].getName().startsWith(filePath)) {
					return true;
				}
			}
			return false;
		}

		private List<File> getFiles(String filePath, String recipient) {
			File[] listFiles = new File(serverDir, recipient).listFiles();
			List<File> files = new ArrayList<File>();

			for(int i = 0; i < listFiles.length; i++) {
				if(listFiles[i].isFile()){
					String fileName = listFiles[i].getName();	
					if (fileName.startsWith(filePath)){
						files.add(listFiles[i]);
					}
				}
			}
			return files;
		}

		private String checkFileRecipient(String filePath){
			String[] extensions = {"cifrado", "chave_secreta",
                                   "assinado", "assinatura", "seguro"};
        	int lastDotIndex = filePath.lastIndexOf(".");
    		filePath = filePath.substring(lastDotIndex + 1, filePath.length());

			if (Arrays.asList(extensions).contains(filePath)){
				return "";
			} else {
				return filePath;
			}
		}

		private void handleFileSending(Socket socket) throws Exception {
            DataOutputStream dataOutputStream =
                new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream =
                new DataInputStream(socket.getInputStream());

            handleUserVerifying(socket);

			String recipient = dataInputStream.readUTF();
			int n_files = dataInputStream.readInt();

			for (int i = 0; i < n_files; i++){

				String fileName = dataInputStream.readUTF();
				System.out.println("Requested file: " + fileName);

				
				File directory = new File(serverDir, recipient);
				if (!directory.exists()){
					directory.mkdir();
				}
				
				File file = new File(directory, fileName);
			
				if (!checkServerFiles(file.getName(), recipient)) {
					System.out.println("File doesn't exist");
					dataOutputStream.writeBoolean(true);
				} else {
					dataOutputStream.writeBoolean(false);	

					List<File> files = getFiles(file.getName(), recipient);

					String extension = checkFileRecipient(files.get(0).getName());

					dataOutputStream.writeUTF(extension);

					if (dataInputStream.readBoolean()){
						File certFile = new File("serverFiles/certificates/" +
                                                 extension + ".keystore");
						if (!certFile.exists()){
							dataOutputStream.writeBoolean(false);
						} else {
							dataOutputStream.writeBoolean(true);
							sendFile(certFile, dataOutputStream);
						}
					}
					
					dataOutputStream.writeInt(files.size());

					for (File serverFile : files) {
                        sendFile(serverFile, dataOutputStream);
					}
				}
			}
		}

		private void sendFile (File file,
                                   DataOutputStream dataOutputStream) throws Exception{
			int bytes = 0;
			FileInputStream fileInputStream = new FileInputStream(file); 
						
            dataOutputStream.writeUTF(file.getName());
			dataOutputStream.writeLong(file.length());

			byte[] buffer = new byte[1024];
			while ((bytes = fileInputStream.read(buffer)) != -1) {
				dataOutputStream.write(buffer, 0, bytes);
				dataOutputStream.flush();
			}

			fileInputStream.close();
			System.out.println("Sent file : " + file.getName());
		}

		private void handleFileReceiving(Socket socket) throws Exception{
            DataOutputStream dataOutputStream =
                new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream =
                new DataInputStream(socket.getInputStream());

            handleUserVerifying(socket);

			String recipient = dataInputStream.readUTF();
			int n_files = dataInputStream.readInt();

			if (dataInputStream.readBoolean()){
				File certFile = new File("serverFiles/certificates/" +
                                         recipient + ".keystore");
				if (!certFile.exists()){
					dataOutputStream.writeBoolean(false);
				} else {
					dataOutputStream.writeBoolean(true);
					sendFile(certFile, dataOutputStream);
				}
			}

			for (int i = 0; i < n_files; i++){
				String fileName = dataInputStream.readUTF();

				System.out.println("Receiving file: " + fileName);

				File directory = new File(serverDir, recipient);
				directory.mkdirs();

				File file = new File(directory, fileName);

				if (file.exists()) {
					System.err.println("File already exists");
					dataOutputStream.writeBoolean(true);
				} else {
					dataOutputStream.writeBoolean(false);
                    receiveFile(file, dataInputStream);
				}
			}
		}

        private void receiveFile(File file,
                                 DataInputStream dataInputStream) throws Exception{
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            
            long size = dataInputStream.readLong();
            
            byte[] buffer = new byte[1024];
            while (size > 0) {
                int bufferSize = (int) Math.min(buffer.length, size);
                int bytesRead = dataInputStream.read(buffer, 0, bufferSize);
                if (bytesRead == -1) {
                    break;
                }
                fileOutputStream.write(buffer, 0, bytesRead);
                size -= bytesRead;
            }
            
            System.out.println("Received file: " + file);
            fileOutputStream.close();
        }
	}
}
