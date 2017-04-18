/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

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
    public static byte[] encrypt() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        TODO: return null;
    }

    public static byte[] saltGenerator() {
        Security.addProvider(new BouncyCastleProvider());

            SecureRandom rand = new SecureRandom();
            byte[] salt = new byte[256];
            rand.nextBytes(salt);
            return salt;

    }

    public static byte[] generateKey(byte[] master_pass) {
      Security.addProvider(new BouncyCastleProvider());

      //will return a byte[] key based upon master_pass using PKCS5_PBKDFT_HMAC
      return null;
    }

}
