package io.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.runtime.api.utils.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static io.crypto.Utils.getPrivateKey;
import static io.crypto.Utils.valueToEmptyOrToString;

public class Decryption {

    public static Object decrypt(Object encryptedString, Object decryptionKey, Object algo) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(valueToEmptyOrToString(algo));
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(valueToEmptyOrToString(decryptionKey)));
            return StringUtils.fromString(new String(cipher.doFinal(Base64.getDecoder()
                    .decode(valueToEmptyOrToString(encryptedString).getBytes()))));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException
                | InvalidKeyException e) {
            return ErrorCreator.createError(StringUtils.fromString(e.toString()));
        }
    }
}
