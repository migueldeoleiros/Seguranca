/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.InputStream;
import java.io.DataInputStream;


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
					ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
					DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

					int command = dataInputStream.readInt();
					switch (command) {
						case 0: //receive files 
							int n_files = dataInputStream.readInt();
							for (int i = 0; i < n_files*2; i++){
								receiveFile(socket, dataInputStream, outputStream);
							}
							break;
						case 1: //send files 
							// TODO
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

		private static void receiveFile(Socket socket, DataInputStream dataInputStream, ObjectOutputStream outputStream) throws Exception{
			int bytes = 0;

			String fileName = dataInputStream.readUTF();
			System.out.println("Receibed file:" + fileName);

			File directory = new File("serverFiles");
			File file = new File(directory, fileName);
			if (file.exists()) {
				System.err.println("File already exists");
				outputStream.writeObject(false);
			}else {
				outputStream.writeObject(true);
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