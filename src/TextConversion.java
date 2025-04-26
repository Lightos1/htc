public class TextConversion {

    public static void thex(String[] flag) {
        if (flag.length != 3) {
            System.out.println("Incorrect amount of arguments, expected 3, received: " + flag.length);
            return;
        }

        switch (flag[1]) {
            case "-l" -> littleEndian(flag[2]);
            case "-b" -> bigEndian(flag[2]);
            default -> System.out.println("Unknown flag: " + flag[2]);
        }
    }

    private static void littleEndian(String arg) {
        if (arg.startsWith("0x")) {
            arg = arg.substring(2);

            if (arg.length() % 2 != 0) {
                System.out.println("Invalid hex string length");
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
                System.out.println("Invalid hex string length");
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
