package com.cas.utils;

import org.springframework.security.crypto.codec.*;
import org.springframework.security.crypto.password.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

public class PasswordUtils extends AbstractPasswordEncoder {

    public static final String ALGORITHM = "PBEWithMD5AndDES";
    public static final String Salt = "63293188";
    private static final int ITERATIONCOUNT = 1000;

    public PasswordUtils() {
    }

    public static byte[] getSalt() throws Exception {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(8);
    }

    public static byte[] getStaticSalt() {
        return "63293188".getBytes();
    }

    private static Key getPBEKey(String password) {
        SecretKey secretKey = null;

        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
            secretKey = keyFactory.generateSecret(keySpec);
        } catch (Exception var4) {
            var4.printStackTrace();
        }

        return secretKey;
    }

    public static String encrypt(String plaintext, String password, String salt) {
        Key key = getPBEKey(password);
        byte[] encipheredData = null;
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt.getBytes(), 1000);

        try {
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(1, key, parameterSpec);
            encipheredData = cipher.doFinal(plaintext.getBytes("utf-8"));
        } catch (Exception var7) {
        }

        return bytesToHexString(encipheredData);
    }

    public static String decrypt(String ciphertext, String password, String salt) {
        Key key = getPBEKey(password);
        byte[] passDec = null;
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt.getBytes(), 1000);

        try {
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(2, key, parameterSpec);
            passDec = cipher.doFinal(hexStringToBytes(ciphertext));
        } catch (Exception var7) {
        }

        return new String(passDec);
    }

    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src != null && src.length > 0) {
            for(int i = 0; i < src.length; ++i) {
                int v = src[i] & 255;
                String hv = Integer.toHexString(v);
                if (hv.length() < 2) {
                    stringBuilder.append(0);
                }

                stringBuilder.append(hv);
            }

            return stringBuilder.toString();
        } else {
            return null;
        }
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString != null && !hexString.equals("")) {
            hexString = hexString.toUpperCase();
            int length = hexString.length() / 2;
            char[] hexChars = hexString.toCharArray();
            byte[] d = new byte[length];

            for(int i = 0; i < length; ++i) {
                int pos = i * 2;
                d[i] = (byte)(charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
            }

            return d;
        } else {
            return null;
        }
    }

    private static byte charToByte(char c) {
        return (byte)"0123456789ABCDEF".indexOf(c);
    }

    @Override
    public byte[] encode(CharSequence charSequence,byte[] salt) {
        return null;
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return false;
    }
}
