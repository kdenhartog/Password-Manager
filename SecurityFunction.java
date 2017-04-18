/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 *
 * @author kyle
 */
public class SecurityFunction {

    public static byte[] hash(byte[] message) throws
            NoSuchAlgorithmException,
            NoSuchProviderException{
        Security.addProvider(new BouncyCastleProvider());

        MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");
        return mda.digest(message);
    }

    //This uses AES-128/CTR/with Padding
    public static byte[] encrypt(byte[] data) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        
        //creating key and cipher
        byte[] key = generateKey();
        Key aesKey = new SecretKeySpec(key, "AES/CTR/NoPadding");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        
        //encrypting
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(data);
        
       return encrypted;
    }
    
    public static byte[] decrypt(byte[] encrypted) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        
        Security.addProvider(new BouncyCastleProvider());

        //creating key and cipher
        byte[] key = generateKey();
        Key aesKey = new SecretKeySpec(key, "AES/CTR/NoPadding");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        
        //decrypting
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        return decrypted;
    }

    public static byte[] randomNumberGenerator() {
        Security.addProvider(new BouncyCastleProvider());

            SecureRandom rand = new SecureRandom();
            byte[] data = new byte[256];
            rand.nextBytes(data);
            return data;

    }

    public static byte[] generateKey() {
      Security.addProvider(new BouncyCastleProvider());

      //will return a byte[] key based upon master_pass using PKCS5_PBKDFT_HMAC
      return null;
    }

}