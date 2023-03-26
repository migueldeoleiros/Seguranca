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
import java.io.OutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.DataInputStream;
import java.io.DataOutputStream;


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
					DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
					DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

					int command = dataInputStream.readInt();
					int n_files = 0;
					switch (command) {
						case 0: //receive files 
							n_files = dataInputStream.readInt();
							for (int i = 0; i < n_files*2; i++){
								receiveFile(socket, dataInputStream, outputStream);
							}
							break;
						case 1: //send files 
							n_files = dataInputStream.readInt();
							for (int i = 0; i < n_files*2; i++){
								sendFile(socket, dataInputStream, outputStream);
							}
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

		private static void receiveFile(Socket socket, DataInputStream dataInputStream, DataOutputStream outputStream) throws Exception{
			int bytes = 0;

			String fileName = dataInputStream.readUTF();
			System.out.println("Receiving file:" + fileName);

			File directory = new File("serverFiles");
			File file = new File(directory, fileName);
			if (file.exists()) {
				System.err.println("File already exists");
				outputStream.writeBoolean(false);
			}else {
				outputStream.writeBoolean(true);
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
		private static void sendFile(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream) throws Exception{
			int bytes = 0;

			String fileName = dataInputStream.readUTF();
			System.out.println("Requested file:" + fileName);


			File file = new File("serverFiles", fileName);
			if (!file.exists()) {
				System.err.println("File doesn't exist");
				dataOutputStream.writeBoolean(false);
			}else {
				FileInputStream fileInputStream = new FileInputStream(file); 
				dataOutputStream.writeBoolean(true);

				dataOutputStream.writeLong(file.length());
				byte[] buffer = new byte[1024];
				while ((bytes = fileInputStream.read(buffer)) != -1) {
					dataOutputStream.write(buffer, 0, bytes);
					dataOutputStream.flush();
				}

				fileInputStream.close();
				System.out.println("Sent file: " + file);
			}
		}
	}
}
