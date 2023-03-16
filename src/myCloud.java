/* Segurança Informática - trabalho 1
   Grupo: 6
   Nuno Infante 55411
   Miguel López 59436
   Marco Martins 41938
   João Nobre 51659
*/
import java.util.ArrayList;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class myCloud {

    public static void main(String[] args) throws UnknownHostException, IOException {
        String address = "localhost";
        int port = 9999;
        ArrayList<String> filenames = new ArrayList<String>();
        String mode = "";

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
                // TODO cifra
                break;
            case "s":
                // TODO assina
                break;
            case "e":
                // TODO cifra e assina
                break;
            case "g":
                // TODO recebe
                break;
            default:
                System.out.println("Invalid command specified.");
                break;
        }
        
        socket.close();
    }

}