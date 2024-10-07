package com.example;

import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAEncryption {
    private KeyPair keyPair;

    public RSAEncryption() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGenerator.initialize(1024, random);
        this.keyPair = keyGenerator.generateKeyPair();
    }

    public String encrypt(String data) throws Exception {
        PublicKey publicKey = this.keyPair.getPublic();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String data) throws Exception {
        PrivateKey privateKey = this.keyPair.getPrivate();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption rsa = new RSAEncryption();
            String encryptedData = rsa.encrypt("Hello World");
            System.out.println("Encrypted Data: " + encryptedData);

            String decryptedData = rsa.decrypt(encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
