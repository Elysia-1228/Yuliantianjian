package com.example.blockchain.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESUtil {
    private static final String ALGORITHM = "AES";
    // In a real production environment, this key should be stored in a secure vault or environment variable.
    // For this demo, we use a hardcoded key (16 bytes for AES-128).
    private static final String KEY_STR = "1234567890123456"; 

    public static String encrypt(String data) throws Exception {
        if (data == null) return null;
        SecretKeySpec keySpec = new SecretKeySpec(KEY_STR.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData) throws Exception {
        if (encryptedData == null) return null;
        SecretKeySpec keySpec = new SecretKeySpec(KEY_STR.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] original = cipher.doFinal(decoded);
        return new String(original, StandardCharsets.UTF_8);
    }
}
