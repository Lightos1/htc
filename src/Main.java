public class Main {
    public static void main(String[] args) {
        paramOne(args);
    }

    private static void paramOne(String[] functionality) {
        switch (functionality[0]) {
            case "--base" -> BaseConversion.base(functionality);
            case "--thex" -> TextConversion.thex(functionality);
            case "--hash" -> Hashing.hash(functionality);
            case "--crypt" -> Crypto.cryption(functionality);
            default -> System.out.println("Unknown arguments.");
        }
    }

}
