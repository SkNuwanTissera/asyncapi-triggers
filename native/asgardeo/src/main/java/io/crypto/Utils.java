package io.crypto;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Utils {
    /**
     * Decode Base64 encoded private string to Private key in PKCS#8 format
     *
     * @param base64PrivateKey
     * @return Private Key in PKCS#8 format
     */
    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        KeyFactory keyFactory = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return privateKey;
    }

    /**
     * Get the value as string or as empty based on the object value.
     *
     * @param value Input value.
     * @return value as a string or empty.
     */
    public static String valueToEmptyOrToString(Object value) {
        return (value == null || value.toString() == "") ? null : value.toString();
    }
}
