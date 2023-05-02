/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/
import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import client.Command;

public class myCloud {

    private static String mode;

    public static void main(String[] args) throws Exception {
        String address = "localhost";
        int port = 9999;
        List<String> filenames = new ArrayList<String>();

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

        if (filenames.isEmpty()){
            System.out.println("No files provided.");
        } else {
            //connect to socket
            Socket socket = new Socket(address, port);

            FileInputStream kfile = new FileInputStream("keystore.maria"); // keystore
            
            KeyStore kstore = null;

            Scanner scanner = new Scanner(System.in);  // Create a Scanner object
            System.out.println("Enter keystore password:");
            String kstorePassword = scanner.nextLine();  // Read user input
            scanner.close();

            try{
                kstore = KeyStore.getInstance("PKCS12");
                kstore.load(kfile, kstorePassword.toCharArray()); // senha
            } catch (Exception e) {
                System.out.println("Keystore's password is incorrect.");
                System.exit(-1);
            }

            Command command = new Command(socket, filenames, kstore, kstorePassword);

            // Perform action based on command
            switch (mode) {
                case "c": {
                    command.c();
                }
                    break;
                case "s": {
                    command.s();
                }
                    break;
                case "e": {
                    command.e();
                }
                    break;

                case "g": {
                    command.g();
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

