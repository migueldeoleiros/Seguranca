/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import client.Command;

public class myCloud {

    private static String mode;

    public static void main(String[] args) throws Exception {
		System.setProperty("javax.net.ssl.trustStore", "truststore.client");
		System.setProperty("javax.net.ssl.trustStorePassword", "123123");	

        String address = "localhost";
        int port = 9999;
        String username = "maria";
        String password = "123123";
        String certificate = "maria.cert";
        String recipient = "";
        List<String> filenames = new ArrayList<String>();

        // Check if arguments were provided
        if (args.length == 0) {
            System.out.println("Usage:");
            System.out.println("myCloud -a <serverAddress> -u <username> -p <password> -c {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -u <username> -p <password> -s {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -u <username> -p <password> -e {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -u <username> -p <password> -g {<filenames>}+");
            System.out.println("myCloud -a <serverAddress> -au <username> <password> <certificado>");
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
            } else if (args[i].equals("-au")) {
                // Get username, password and certificate
                mode = args[i].substring(1);
                username = args[i+1];
                password = args[i+2];
                certificate = args[i+3];
                break;
            } else if (args[i].equals("-u")) {
                // Get username
                username = args[i+1];
                i++;
            } else if (args[i].equals("-p")) {
                // Get password
                password = args[i+1];
                i++;
            } else if (args[i].equals("-d")) {
                // Get recipient
                recipient = args[i+1];
                i++;
            } else if (args[i].equals("-c") || args[i].equals("-s")
                       || args[i].equals("-e") || args[i].equals("-g")) {
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

        //if there is no recipient indicated it's sent to it's own directory
        if(recipient == ""){
            recipient = username;
        }

        if (filenames.isEmpty() &&
            (mode == "c" || mode == "s" || mode == "e" || mode == "g")){
            System.out.println("No files provided.");
        } else {
            //connect to socket
            SocketFactory sf = SSLSocketFactory.getDefault( );
            Socket socket = sf.createSocket(address, port);

            Command command = new Command(socket, username, password);

            // Perform action based on command
            switch (mode) {
                case "c": {
                    command.c(recipient, filenames);
                }
                    break;
                case "s": {
                    command.s(recipient, filenames);
                }
                    break;
                case "e": {
                    command.e(recipient, filenames);
                }
                    break;
                case "g": {
                    command.g(recipient, filenames);
                }
                    break;
                case "au": {
                    command.au(username, password, certificate);
                }
                    break;
                default:
                    System.out.println("Invalid command specified.");
                    break;
            }       
                socket.close();
        }
    }
}

