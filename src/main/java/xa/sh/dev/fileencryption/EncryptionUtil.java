package xa.sh.dev.fileencryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;

    public static byte[] encrypt(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = getKey(key);

        // Generate random IV
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(data);

        // Prepend IV to encrypted data
        byte[] output = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, output, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, output, IV_SIZE, encrypted.length);
        return output;
    }

    public static byte[] decrypt(byte[] encryptedWithIV, String key) throws Exception {
        SecretKeySpec secretKey = getKey(key);

        // Extract IV and encrypted data
        byte[] iv = Arrays.copyOfRange(encryptedWithIV, 0, IV_SIZE);
        byte[] encrypted = Arrays.copyOfRange(encryptedWithIV, IV_SIZE, encryptedWithIV.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    private static SecretKeySpec getKey(String myKey) {
        byte[] key = Arrays.copyOf(myKey.getBytes(StandardCharsets.UTF_8), 16); // AES-128
        return new SecretKeySpec(key, "AES");
    }
}
