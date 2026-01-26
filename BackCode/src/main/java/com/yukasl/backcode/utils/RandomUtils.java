package com.yukasl.backcode.utils;

import java.security.SecureRandom;

public class RandomUtils {
    private static final char[] CHAR_POOL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String generateRandomString(int length) {
        char[] result = new char[length];
        for (int i = 0; i < length; i++)
            result[i] = CHAR_POOL[SECURE_RANDOM.nextInt(CHAR_POOL.length)];
        return new String(result);
    }
}