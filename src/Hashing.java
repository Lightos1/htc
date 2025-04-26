import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing {

    public static void hash(String[] args) {
        if (args.length != 3) {
            System.out.println("Incorrect amount of arguments, expected 3, received: " + args.length);
            return;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(args[1].substring(1));

            byte[] hashBytes = digest.digest(args[2].getBytes());

            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hashBytes.length; i++) {
                hexString.append(String.format("%02x", hashBytes[i]));
            }

            System.out.println(hexString);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not identify hashing algorithm: " + e.getMessage());
        }
    }

}
