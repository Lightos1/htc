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
            case "--help" -> help();
            default -> System.out.println("Unknown arguments.");
        }
    }

    private static void help() {
        System.out.println("Available Commands:\n");

        System.out.println("--base");
        System.out.println("\tConvert between hexadecimal and decimal.");
        System.out.println("\tArguments:");
        System.out.println("\t\tValue to convert. Prefix with '0x' for hexadecimal.\n");

        System.out.println("--thex");
        System.out.println("\tConvert between text and hexadecimal.");
        System.out.println("\tFlags:");
        System.out.println("\t\t-l\tLittle-endian encoding");
        System.out.println("\t\t-b\tBig-endian encoding");
        System.out.println("\tArguments:");
        System.out.println("\t\tText to convert. Prefix with '0x' to decode from hex.\n");

        System.out.println("--hash");
        System.out.println("\tHash a text input using a specified algorithm.");
        System.out.println("\tFlags:");
        System.out.println("\t\t-<algorithm>\tHashing algorithm (e.g., SHA-256, MD5)");
        System.out.println("\tArguments:");
        System.out.println("\t\tText to be hashed.\n");

        System.out.println("--crypt");
        System.out.println("\tEncrypt, decrypt, or generate cryptographic keys.");
        System.out.println("\tFlags:");
        System.out.println("\t\t-<algorithm>\tCrypto algorithm (Supported: RSA, AES)");
        System.out.println("\t\t-gen\tGenerate a key pair or secret key.");
        System.out.println("\t\t\tArguments:");
        System.out.println("\t\t\t\tBit size (e.g., 2048 for RSA, 256 for AES)");
        System.out.println("\t\t-en\tEncrypt a message.");
        System.out.println("\t\t-de\tDecrypt a message.");
        System.out.println("\tArguments for -en and -de:");
        System.out.println("\t\tKey (public, private, or secret key in Base64)");
        System.out.println("\t\tMessage to encrypt or decrypt.\n");
    }

}
