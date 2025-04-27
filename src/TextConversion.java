import java.util.Base64;

public class TextConversion {

    public static void thex(String[] flag) {
        if (flag.length != 3) {
            System.err.println("Incorrect amount of arguments, expected 3, received: " + flag.length);
            return;
        }

        switch (flag[1]) {
            case "-l" -> littleEndian(flag[2]);
            case "-b" -> bigEndian(flag[2]);
            default -> System.err.println("Unknown flag: " + flag[2]);
        }
    }

    public static void b64(String[] flag) {
        if (flag.length != 3) {
            System.err.println("Incorrect amount of arguments, expected 3, received: " + flag.length);
            return;
        }

        if (flag[1].startsWith("-en")) {
            byte[] encodedBytes = flag[2].getBytes();
            System.out.println(Base64.getEncoder().encodeToString(encodedBytes));
        } else if (flag[1].startsWith("-de")) {
            byte[] decodedBytes = Base64.getDecoder().decode(flag[2]);
            String decodedString = new String(decodedBytes);
            System.out.println(decodedString);
        } else {
            System.err.println("Unknown parameter");
        }
    }

    private static void littleEndian(String arg) {
        if (arg.startsWith("0x")) {
            arg = arg.substring(2);

            if (arg.length() % 2 != 0) {
                System.err.println("Invalid hex string length");
                return;
            }

            byte[] bytes = new byte[arg.length() / 2];
            for (int i = 0; i < arg.length(); i += 2) {
                bytes[i / 2] = (byte) Integer.parseInt(arg.substring(i, i + 2), 16);
            }

            for (int i = 0; i < bytes.length / 2; i++) {
                byte temp = bytes[i];
                bytes[i] = bytes[bytes.length - 1 - i];
                bytes[bytes.length - 1 - i] = temp;
            }

            String text = new String(bytes);
            System.out.println(text);
        } else {
            byte[] bytes = arg.getBytes();
            StringBuilder reverseHex = new StringBuilder();

            for (int i = bytes.length - 1; i >= 0; i--) {
                reverseHex.append(String.format("%02x", bytes[i]));
            }
            System.out.println("0x" + reverseHex);
        }
    }

    private static void bigEndian(String arg) {
        if (arg.startsWith("0x")) {
            arg = arg.substring(2);
            if (arg.length() % 2 != 0) {
                System.err.println("Invalid hex string length");
                return;
            }

            byte[] bytes = new byte[arg.length() / 2];

            for (int i = 0; i < arg.length(); i += 2) {
                bytes[i / 2] = (byte) Integer.parseInt(arg.substring(i, i + 2), 16);
            }

            String text = new String(bytes);
            System.out.println(text);
        } else {
            byte[] bytes = arg.getBytes();
            StringBuilder hex = new StringBuilder();

            for (int i = 0; i < bytes.length; i++) {
                hex.append(String.format("%02x", bytes[i]));
            }

            System.out.println("0x" + hex);
        }
    }

}
