import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

    public static void cryption(String[] args) {
        String alg = args[1].substring(1);
        String flags = args[2].substring(1);

        switch (flags) {
            case "gen" -> {
                if (args.length != 4) {
                    System.out.println("Incorrect amount of arguments, expected 4, received: " + args.length);
                }
                int bits = Integer.parseInt(args[3].substring(1));
                generateKeys(alg, bits);
            }
            case "en" -> {
                if (args.length != 5) {
                    System.out.println("Incorrect amount of arguments, expected 5, received: " + args.length);
                }
                Object key = alg.equalsIgnoreCase("AES") ? getSecretKey(args[3]) : getPublicKey(args[3], alg);
                String message = args[4];

                encrypt(alg, key, message);
            }
            case "de" -> {
                if (args.length != 5) {
                    System.out.println("Incorrect amount of arguments, expected 5, received: " + args.length);
                }
                Object key = alg.equalsIgnoreCase("AES") ? getSecretKey(args[3]) : getPrivateKey(args[3], alg);
                String message = args[4];

                decrypt(alg, key, message);
            }
            default -> System.out.println("Invalid arguments");
        }
    }

    private static void generateKeys(String alg, int bits) {
        try {
            if (alg.equalsIgnoreCase("AES")) {
                KeyGenerator keyGen = KeyGenerator.getInstance(alg);
                SecureRandom random = SecureRandom.getInstanceStrong();
                keyGen.init(bits, random);
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Secret key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            } else {
                KeyPairGenerator genKey = KeyPairGenerator.getInstance(alg);
                SecureRandom random = SecureRandom.getInstanceStrong();
                genKey.initialize(bits, random);
                KeyPair keyPair = genKey.generateKeyPair();
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                System.out.println("Public key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
                System.out.println("Private key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid arguments: " + e.getMessage());
        }
    }

    private static SecretKey getSecretKey(String key) {
        byte[] decoded = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decoded, 0, decoded.length, "AES");
    }

    private static PublicKey getPublicKey(String key, String alg) {
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(alg);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
        System.err.println("Invalid public key: " + key);
        System.exit(-1);
        return null;
    }

    private static PrivateKey getPrivateKey(String key, String alg) {
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(alg);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
        System.err.println("Invalid private key: " + key);
        System.exit(-1);
        return null;
    }

    private static void encrypt(String alg, Object key, String message) {
        try {
            Cipher encrypt = Cipher.getInstance(alg);
            if (key instanceof PublicKey) {
                encrypt.init(Cipher.ENCRYPT_MODE, (PublicKey) key);
            } else if (key instanceof SecretKey) {
                encrypt.init(Cipher.ENCRYPT_MODE, (SecretKey) key);
            } else {
                throw new IllegalArgumentException("Unsupported key type");
            }

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = encrypt.doFinal(messageBytes);
            System.out.println("\n" + Base64.getEncoder().encodeToString(encryptedBytes));
        } catch (Exception e) {
            System.err.println("Invalid arguments: " + e.getMessage());
        }
    }

    private static void decrypt(String alg, Object key, String message) {
        try {
            Cipher decrypt = Cipher.getInstance(alg);
            if (key instanceof PrivateKey) {
                decrypt.init(Cipher.DECRYPT_MODE, (PrivateKey) key);
            } else if (key instanceof SecretKey) {
                decrypt.init(Cipher.DECRYPT_MODE, (SecretKey) key);
            } else {
                throw new IllegalArgumentException("Unsupported key type");
            }

            byte[] encryptedBytes = Base64.getDecoder().decode(message);
            byte[] decryptedBytes = decrypt.doFinal(encryptedBytes);
            System.out.println("\n" + new String(decryptedBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Invalid arguments: " + e.getMessage());
        }
    }

}
