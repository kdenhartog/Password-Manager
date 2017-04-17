package passwordmanager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.Closeable;
import java.util.Scanner;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.util.Arrays;

public class PasswordManager 
{
    private static class Registry 
        implements Closeable 
    {
        private class Master
        {
            private final byte[] zero = 
                { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, };
            private byte[] salt = zero.clone();
            private byte[] hash = zero.clone();
            
            Master(Path masterpath) 
                throws IOException, NoSuchAlgorithmException
            {
                if (Files.isReadable(masterpath))
                {
                    if (Files.size(masterpath) != 2 * zero.length)
                        throw new IOException();
                    try (InputStream fp = Files.newInputStream(masterpath))
                    {
                        if (fp.read(salt) != salt.length
                            || fp.read(hash) != hash.length)
                            throw new IOException();
                    }
                    return;
                }
                
                new SecureRandom().nextBytes(salt);
                hash = input_secret();
                Files.write(masterpath,
                    Arrays.concatenate(salt, hash));
            }
                        
            private byte[] input_secret() 
                throws
                    UnsupportedEncodingException, 
                    NoSuchAlgorithmException,
                    IOException
            {
                // System.out.println(System.console());
                // byte[] secret = 
                //     new String(
                //         System.console().readPassword(
                //             "input master secret: "))
                //     .getBytes("utf-8");
                // doesn't work with netbeans,
                // System.console() returns null
                
                System.out.print("input secret: ");
                BufferedReader br = 
                    new BufferedReader(
                        new InputStreamReader(System.in));
                byte[] secret = br.readLine().getBytes("utf-8");
                MessageDigest gut = MessageDigest.getInstance("sha-512");
                gut.reset();
                gut.update(salt);
                gut.update(secret);
                Arrays.fill(secret, (byte)0);
                return gut.digest();
            }
            
            boolean validate() 
                throws 
                    UnsupportedEncodingException, 
                    NoSuchAlgorithmException,
                    IOException
            {
                return 
                    Arrays.areEqual(
                        input_secret(), 
                        hash);
            }
        }
        
        final Master master;
        
        private Registry(
            Path masterpath, 
            Path passwdpath) 
            throws IOException, NoSuchAlgorithmException
        {
            check_filesystem(masterpath, passwdpath);
            master = new Master(masterpath);
        }
        private Registry(Path path) 
            throws IOException, NoSuchAlgorithmException
        {
            this(
                path.resolve("master_passwd"),
                path.resolve("passwd_file"));
        }
        Registry()
            throws IOException, NoSuchAlgorithmException
        {
            this(Paths.get("."));
        }
        
        private void check_filesystem(
            Path masterpath, 
            Path passwdpath) 
            throws IOException
        {
            if (!Files.isReadable(masterpath)
                || !Files.isReadable(passwdpath)
                || !Files.isWritable(passwdpath))
            {
                Files.deleteIfExists(masterpath);
                Files.deleteIfExists(passwdpath);
            }
        }
        
        @Override
        public void close() 
            throws IOException 
        {
            
            //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
    }
        
    /*public static void main(String[] args) throws Exception 
    {
        try
        {
            // test registry
            Registry reg = new Registry();
            System.out.println(reg.master.validate());
            
        }
        catch (Exception e)
        {
            throw e;
        }
        
        System.in.read();
        System.exit(0);
    }*/
}
