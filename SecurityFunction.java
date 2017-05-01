import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author Kyle Den Hartog, Nicholas Kao, and Doug Ives
 */
public class SecurityFunction {

    public static byte[] hash(byte[] message) throws
            NoSuchAlgorithmException,
            NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");
        return mda.digest(message);
    }

    //This uses AES-128/CTR/with Padding
    public static byte[] encrypt(byte[] input, SecretKey key) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            FileNotFoundException,
            IOException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        //Create IV
        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[aes.getBlockSize()];
        rand.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);

        //encrypt
        aes.init(Cipher.ENCRYPT_MODE, key, ivParam);
        byte[] encrypted = aes.doFinal(input);

        //combine IV and encrypted and return
        byte[] iv_and_encrypted = Arrays.concatenate(iv, encrypted);
        return iv_and_encrypted;
    }

    public static byte[] decrypt(byte[] input, SecretKey key) throws
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            IOException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException,
            BadPaddingException,
            NoSuchProviderException,
            FileNotFoundException,
            InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        //get IV
        byte[] iv = new byte[aes.getBlockSize()];
        iv = Arrays.copyOf(input, iv.length);
        IvParameterSpec ivParam = new IvParameterSpec(iv);

        //get data to decrypt
        byte[] encrypted = Arrays.copyOfRange(input, iv.length, input.length);

        //decrypt
        aes.init(Cipher.DECRYPT_MODE, key, ivParam);
        byte[] decrypted = aes.doFinal(encrypted);
        return decrypted;
    }

    public static byte[] hmac(byte[] input, SecretKey key) throws
            IOException,
            FileNotFoundException,
            NoSuchProviderException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

        //initialize SHA512Hmac using master_passwd key
        Mac mac = Mac.getInstance("HmacSHA512", "BC");
        mac.init(key);

        //return hmac
        return mac.doFinal(input);
    }

    public static byte[] randomNumberGenerator(int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom rand = new SecureRandom();
        byte[] data = new byte[size];
        rand.nextBytes(data);
        return data;
    }

    public static SecretKey generateKey(String password, byte[] salt) throws
            FileNotFoundException,
            IOException,
            NoSuchProviderException,
            InvalidKeySpecException,
            NoSuchAlgorithmException {
            Security.addProvider(new BouncyCastleProvider());
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");

            //generate key
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey tmpKey = factory.generateSecret(spec);
            SecretKey key = new SecretKeySpec(tmpKey.getEncoded(), "AES");
            return key;
    }
}
