/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
 * @author Kyle Den Hartog, Nicholas Kao, 
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
    public static byte[] encrypt(byte[] input) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            FileNotFoundException,
            IOException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException {

        Security.addProvider(new BouncyCastleProvider());
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");

        //Create IV
        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[aes.getBlockSize()];
        rand.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        
        //Create Key
        Key key = generateKey();

        //encrypt
        aes.init(Cipher.ENCRYPT_MODE, key, ivParam);
        byte[] encrypted = aes.doFinal(input);

        //combine IV and encrypted and return
        byte[] data = Arrays.concatenate(iv, encrypted);
        return data;
    }

    public static byte[] decrypt(byte[] input) throws
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            IOException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException,
            BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");

        //get IV
        byte[] iv = new byte[aes.getBlockSize()];
        iv = Arrays.copyOf(input, iv.length);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        
        //get Key
        Key key = generateKey();
        
        //get data to decrypt
        byte[] encrypted = new byte[input.length - iv.length];
        encrypted= Arrays.copyOfRange(input, iv.length, input.length);
        
        //decrypt
        aes.init(Cipher.DECRYPT_MODE, key, ivParam);
        byte[] decrypted = aes.doFinal(encrypted);
        return decrypted;
    }

    public static byte[] randomNumberGenerator(int size) {
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom rand = new SecureRandom();
        byte[] data = new byte[size];
        rand.nextBytes(data);
        return data;

    }

    private static Key generateKey() throws FileNotFoundException, IOException {
        try {
            Security.addProvider(new BouncyCastleProvider());
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            //get Salt and Hash for key generation
            //Used for master_passwd path
            String master_passwd_path = System.getProperty("user.dir");
            master_passwd_path += "/master_passwd";
            Path path = Paths.get(master_passwd_path);
            byte[] data = Files.readAllBytes(path);
            byte[] salt = new byte[256];
            //get salt
            System.arraycopy(data, 0, salt, 0, 256);
            
            //get hash
            byte [] hashArr = new byte[data.length - 256];
            System.arraycopy(data, salt.length, hashArr, 0, hashArr.length);
            String hash = String.format("%064x", new java.math.BigInteger(1, hashArr));

            KeySpec spec = new PBEKeySpec(hash.toCharArray(), salt, 65536, 128);
            SecretKey tmpKey = factory.generateSecret(spec);
            SecretKey key = new SecretKeySpec(tmpKey.getEncoded(), "AES");
            return key;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(SecurityFunction.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
}
