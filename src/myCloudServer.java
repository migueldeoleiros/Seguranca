/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;


public class myCloudServer {

	public static void main(String[] args) {
		System.out.println("servidor: main");
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
			sSoc = new ServerSocket(port);
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
					DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
					DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

					int command = dataInputStream.readInt();
					
					switch (command) {
						case 0: //receive files 
							receiveFile(socket, dataInputStream, dataOutputStream);
							break;
						case 1: //send files 
							sendFile(socket, dataInputStream, dataOutputStream);
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

		private static boolean checkServerFiles(String filePath) {
			File[] listFiles = new File("serverFiles").listFiles();

			for(int i = 0; i < listFiles.length; i++) {
				if(listFiles[i].isFile()){
					String fileName = listFiles[i].getName();
				
					if (fileName.startsWith(filePath)){
						return true;
					}
				}
			}
			return false;
		}

		private static List<File> getFiles(String filePath) {
			File[] listFiles = new File("serverFiles").listFiles();
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

		private static void sendFile(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream) throws Exception {
			int n_files = dataInputStream.readInt();

			for (int i = 0; i < n_files; i++){

				int bytes = 0;

				String fileName = dataInputStream.readUTF();
				System.out.println("Requested file: " + fileName);

				File directory = new File("serverFiles");
				if (!directory.exists()){
					directory.mkdir();
				}
				
				File file = new File(directory, fileName);

				if (!checkServerFiles(file.getName())) {
					System.out.println("File doesn't exist");
					dataOutputStream.writeBoolean(true);
				} else {
					dataOutputStream.writeBoolean(false);	

					List<File> files = getFiles(file.getName());

					dataOutputStream.writeInt(files.size());

					for (File serverFile : files) {
						FileInputStream fileInputStream = new FileInputStream(serverFile); 
						
						System.out.println(serverFile.getName());
						dataOutputStream.writeUTF(serverFile.getName());
						dataOutputStream.writeLong(serverFile.length());
						byte[] buffer = new byte[1024];
						while ((bytes = fileInputStream.read(buffer)) != -1) {
							dataOutputStream.write(buffer, 0, bytes);
							dataOutputStream.flush();
						}

						fileInputStream.close();
						System.out.println("Sent file : " + serverFile.getName());
					}
				}
			}
		}

		private static void receiveFile(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream) throws Exception{
			int n_files = dataInputStream.readInt();

			for (int i = 0; i < n_files; i++){
				int bytes = 0;

				String fileName = dataInputStream.readUTF();
				System.out.println("Receiving file: " + fileName);

				File directory = new File("serverFiles");
				if (!directory.exists()){
					directory.mkdir();
				}

				File file = new File(directory, fileName);

				if (file.exists()) {
					System.err.println("File already exists");
					dataOutputStream.writeBoolean(true);
				} else {
					dataOutputStream.writeBoolean(false);
					FileOutputStream fileOutputStream = new FileOutputStream(file);

					long size = dataInputStream.readLong();

					byte[] buffer = new byte[1024];
					while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
						fileOutputStream.write(buffer, 0, bytes);
						size -= bytes;
					}

					System.out.println("Received file: " + file);
					fileOutputStream.close();
				}
			}
		}
	}
}