public class BaseConversion {

    public static void base(String[] flag) {
        if (flag.length != 2) {
            System.out.println("Incorrect amount of arguments, expected 2, received: " + flag.length);
        }

        try {
            if (flag[1].startsWith("0x")) {
                toDec(flag[1].substring(2));
            } else {
                toHex(flag[1]);
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number format: " + e.getMessage());
        }
    }

    private static void toHex(String decValue) {
        System.out.println("0x" + Integer.toHexString(Integer.parseInt(decValue)));
    }

    private static void toDec(String hexValue) {
        System.out.println(Integer.parseInt(hexValue, 16));
    }

}
