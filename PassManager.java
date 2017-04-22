import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author Kyle Den Hartog, Nicholas Kao, and Doug Ives
 */
public class PassManager {

    private static SecretKey key;

    private static void checkIntegrity() throws
            IOException,
            FileNotFoundException,
            NoSuchProviderException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            InvalidKeySpecException {
        //Get data from passwd_file
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";
        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);

        byte[] lastHmac = Arrays.copyOf(data, 64);
        byte[] encrypted = Arrays.copyOfRange(data, 64, data.length);
        byte[] currentHmac = SecurityFunction.hmac(encrypted, key);

        if (Arrays.areEqual(lastHmac, currentHmac)) {
            System.out.print("PASSED!\n");
        } else {
            System.out.println("FAILED!\n");
        }
    }

    private static void registerAccount() throws
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            NoSuchProviderException,
            FileNotFoundException,
            IOException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        Scanner sc = new Scanner(System.in);
        //Get Domain Name
        System.out.print("\nPlease enter the domain name: ");
        String domain = sc.next();

        //Get Username
        System.out.print("Please enter your username: ");
        String username = sc.next();

        //Get password
        System.out.print("Please enter your password: ");
        String password = sc.next();

        //get data from passwd_file
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";
        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);

        //strip hmac
        byte[] data_no_hmac = Arrays.copyOfRange(data, 64, data.length);
        byte[] decrypted = SecurityFunction.decrypt(data_no_hmac, key);

        //Lookup account to see if it already exists if not write it to file
        if (accountLookup(domain, username, decrypted) == null) {
            //create account using " " for acc attribute seperation and "!" used for acc seperation
            String account = domain + " " + username + " " + password + "!";
            byte[] dataBytes = account.getBytes("UTF-8");

            //append account to end of stored accounts data
            byte[] newData = Arrays.concatenate(decrypted, dataBytes);

            //reencrypt data
            byte[] encrypted = SecurityFunction.encrypt(newData, key);

            //generate hmac
            byte[] hmac = SecurityFunction.hmac(encrypted, key);
            byte[] hmac_and_encrypted = Arrays.concatenate(hmac, encrypted);

            //write to file
            try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                output.write(hmac_and_encrypted);
                output.close();
                System.out.println("USER ACCOUNT REGISTERED!\n");
            }
        } else {
            System.out.println("USER ACCOUNT ALREADY EXISTS!\n");
        }
    }

    private static void deleteAccount() throws
            IOException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            FileNotFoundException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        Scanner sc = new Scanner(System.in);
        //Get Domain Name
        System.out.print("\nPlease enter the domain name: ");
        String domain = sc.next();
        //Get Username
        System.out.print("Please enter your username: ");
        String username = sc.next();
        //Get password
        System.out.print("Please enter your password: ");
        String password = sc.next();

        //get data from passwd_file
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";
        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);

        //strip hmac
        byte[] data_no_hmac = Arrays.copyOfRange(data, 64, data.length);
        byte[] decrypted = SecurityFunction.decrypt(data_no_hmac, key);

        //check if account exists
        if (accountLookup(domain, username, decrypted) != null) {
            String dataString = new String(decrypted, "UTF-8");
            String[] accounts = dataString.split("!");
            String account = domain + " " + username;
            //search through accounts and delete account
            for (int i = 0; i < accounts.length; i++) {
                if (accounts[i].contains(account)) {
                    accounts[i] = null;
                    break;
                }
            }

            //rebuild list of accounts by filling the removed
            String newAccList = "";
            for (int i = 0; i < accounts.length; i++) {
                if (accounts[i] != null) {
                    newAccList += accounts[i] + "!";
                }
            }

            //turn accounts list back into bytes
            byte[] bytesData = newAccList.getBytes("UTF-8");

            //encrypt data
            byte[] encrypted = SecurityFunction.encrypt(bytesData, key);

            //generate hmac and append data
            byte[] hmac = SecurityFunction.hmac(encrypted, key);
            byte[] hmac_and_encrypted = Arrays.concatenate(hmac, encrypted);

            //write to file
            try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                output.write(hmac_and_encrypted);
                output.close();
                System.out.println("USER ACCOUNT REMOVED!\n");
            }
        } else {//account not found
            System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
        }
    }

    /*  This is a function to change an accounts password given a domain name,
    *   a username, the old password, and the new password.
     */
    private static void changeAccount() throws
            IOException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            FileNotFoundException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        Scanner sc = new Scanner(System.in);
        //Get Domain Name
        System.out.print("\nPlease enter the domain name: ");
        String domain = sc.next();
        //Get Username
        System.out.print("Please enter your username: ");
        String username = sc.next();
        //Get old password
        System.out.print("Please enter your old password: ");
        String oldpass = sc.next();
        //Get new password
        System.out.print("Please enter your new password: ");
        String newpass = sc.next();
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";
        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);

        //strip hmac
        byte[] data_no_hmac = Arrays.copyOfRange(data, 64, data.length);
        byte[] decrypted = SecurityFunction.decrypt(data_no_hmac, key);

        //perform account change
        if (accountLookup(domain, username, decrypted) != null) {
            String dataString = new String(decrypted, "UTF-8");
            String[] accounts = dataString.split("!");
            String account = domain + " " + username;
            String updated = domain + " " + username + " " + newpass;
            //search through accounts and delete account
            for (int i = 0; i < accounts.length; i++) {
                if (accounts[i].contains(account)) {
                    accounts[i] = updated;
                    break;
                }
            }
            //rebuild list of accounts and change to byte[]
            String newAccList = "";
            for (String acc : accounts) {
                newAccList += acc + "!";
            }
            byte[] bytesData = newAccList.getBytes("UTF-8");

            //encrypt new data
            byte[] encrypted = SecurityFunction.encrypt(bytesData, key);

            //generate new hmac and append
            byte[] hmac = SecurityFunction.hmac(encrypted, key);
            byte[] hmac_and_encrypted = Arrays.concatenate(hmac, encrypted);

            //write to file
            try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                output.write(hmac_and_encrypted);
                output.close();
                System.out.println("USER ACCOUNT UPDATED!\n");
            }
        } else {//account not found
            System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
        }
    }

    /*  This is a feature required by the assignment where it reads in a domain
    *   from the user and returns all usernames and passwords matching that domain.
     */
    private static void getPassword() throws
            IOException,
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException,
            BadPaddingException,
            NoSuchProviderException,
            FileNotFoundException,
            InvalidKeySpecException {
        Scanner sc = new Scanner(System.in);
        System.out.print("\nPlease enter a domain: ");
        String domain = sc.next();

        //reads in all data from /passwd_file
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";
        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);

        //strip hmac
        byte[] data_no_hmac = Arrays.copyOfRange(data, 64, data.length);
        byte[] decrypted = SecurityFunction.decrypt(data_no_hmac, key);

        //search data for account and print all found based on domain
        String dataString = new String(decrypted, "UTF-8");
        String[] accounts = dataString.split("!");
        String id = domain;
        for (String account : accounts) {
            if (account.contains(id)) {
                String[] accArr = account.split(" ");
                System.out.print("username " + accArr[1] + " password " + accArr[2] + "\n");
            }
        }
    }

    //This is used upon startup for the first time or if a file is missing to
    private static void setup() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            FileNotFoundException,
            IOException,
            InvalidKeyException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException {
        Scanner sc = new Scanner(System.in);
        //create passwd_file path
        String passwd_file_string = System.getProperty("user.dir");
        passwd_file_string += "/passwd_file";

        //Used for master_passwd path
        String master_passwd_string = System.getProperty("user.dir");
        master_passwd_string += "/master_passwd";

        //initialize file paths
        Path passwd_file_path = Paths.get(passwd_file_string);
        Path master_passwd_path = Paths.get(master_passwd_string);

        //initialize files
        File master_passwd_file = new File(master_passwd_string);
        File passwd_file = new File(passwd_file_string);

        //delete old files if they exists
        Files.deleteIfExists(passwd_file_path);
        Files.deleteIfExists(master_passwd_path);

        //create files
        passwd_file.createNewFile();
        master_passwd_file.createNewFile();

        //get master password
        System.out.print("\nPlease provide a master password: ");
        String master_passwd = sc.next();
        byte[] password = master_passwd.getBytes();

        //get salt and combine with master password
        byte[] salt = SecurityFunction.randomNumberGenerator(256);
        byte[] salted_password = Arrays.concatenate(salt, password);

        //setup master_passwd file
        byte[] hash = SecurityFunction.hash(salted_password);
        byte[] salt_and_hash = Arrays.concatenate(salt, hash);
        //write data to master_passwd file
        try (FileOutputStream output = new FileOutputStream("master_passwd")) {
            output.write(salt_and_hash);
            output.close();
        }

        //generate key kept in memory during the use of the program
        key = SecurityFunction.generateKey(master_passwd);

        //get hash for passwd_file and append to file
        byte[] passwd_file_data = Files.readAllBytes(passwd_file_path);
        byte[] encrypted = SecurityFunction.encrypt(passwd_file_data, key);
        byte[] hmac = SecurityFunction.hmac(encrypted, key);
        byte[] hmac_and_encrypted = Arrays.concatenate(hmac, encrypted);
        //write data to passwd_file
        try (FileOutputStream output = new FileOutputStream("passwd_file")) {
            output.write(hmac_and_encrypted);
            output.close();
        }
    }

    //This is a helper function to help do a password check during startup
    private static boolean passwordCheck(String entry) throws
            FileNotFoundException,
            IOException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        //get contents
        String master_passwd_path = System.getProperty("user.dir");
        master_passwd_path += "/master_passwd";
        Path path = Paths.get(master_passwd_path);
        byte[] contents = Files.readAllBytes(path);

        //get salt and password as bytes for comparison
        byte[] salt = Arrays.copyOf(contents, 256);
        byte[] password = entry.getBytes();

        //concatenate the salt and the password then hash it
        byte[] salted_password = Arrays.concatenate(salt, password);
        byte[] hashed = SecurityFunction.hash(salted_password);

        return (Arrays.areEqual(contents, Arrays.concatenate(salt, hashed)));
    }

    //This will be used for checking if accounts exist
    private static String accountLookup(String domain, String user, byte[] data) throws UnsupportedEncodingException {
        String dataString = new String(data, "UTF-8");
        String[] accounts = dataString.split("!");
        String id = domain + " " + user;

        //search through accounts
        for (String account : accounts) {
            if (account.contains(id)) {
                return account;
            }
        }
        return null;
    }

    //This is a helper function to verify that both files exist
    private static boolean fileCheck() {
        //Used for passwd_file path
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";

        //Used for master_passwd path
        String master_passwd_path = System.getProperty("user.dir");
        master_passwd_path += "/master_passwd";

        File passwd_file = new File(passwd_file_path);
        File master_passwd = new File(master_passwd_path);

        return (passwd_file.exists() && master_passwd.exists());
    }

    //this method is used to authenticate the user and verify the integrity of passwd_file on startup
    private static void startup() throws
            IOException,
            NoSuchAlgorithmException,
            FileNotFoundException,
            NoSuchProviderException,
            InvalidKeyException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException {
        String master_passwd;
        Scanner sc = new Scanner(System.in);

        System.out.println("\nWelcome to your password manager");
        if (!fileCheck()) {
            setup();
        } else {
            System.out.print("\nPlease enter your master password: ");
            master_passwd = sc.next();

            //verifies password are correct or exits after 5 attempts
            int counter = 0;
            while (!passwordCheck(master_passwd)) {
                System.out.println("WRONG MASTER PASSWORD\n");
                System.out.print("Please re-enter your master password: ");
                master_passwd = sc.next();
                counter++;
                if (counter == 5) {
                    System.out.println("Password attempts exceeded. Exiting...");
                    System.exit(0);
                }
            }
            //generate key kept in memory during the use of the program
            key = SecurityFunction.generateKey(master_passwd);

            //integrity check
            String passwd_file_path = System.getProperty("user.dir");
            passwd_file_path += "/passwd_file";
            Path path = Paths.get(passwd_file_path);
            byte[] data = Files.readAllBytes(path);

            byte[] lastHmac = Arrays.copyOf(data, 64);
            byte[] encrypted = Arrays.copyOfRange(data, 64, data.length);
            byte[] currentHmac = SecurityFunction.hmac(encrypted, key);

            if (Arrays.areEqual(lastHmac, currentHmac)) {
            } else {
                System.out.println("INTEGRITY CHECK OF PASSWORD FILE FAILED\n");
            }
        }
    }

    private static int mainMenu() {
        Scanner sc = new Scanner(System.in);
        System.out.println("\n1 - Check Integrity");
        System.out.println("2 - Register Account");
        System.out.println("3 - Delete Account");
        System.out.println("4 - Change Account");
        System.out.println("5 - Get Password");
        System.out.println("6 - Exit");
        int option = 0;

        do {
            System.out.print("Please enter an integer between 1 and 6 corresponding with the option you would like to select: ");
            while (!sc.hasNextInt()) {
                System.out.println("Invalid input.");
                sc.next();
            }
            option = sc.nextInt();
        } while (!(option >= 1 && option <= 6));
        return option;
    }

    /**
     *
     * @param args
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws java.io.FileNotFoundException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.security.spec.InvalidParameterSpecException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static void main(String[] args) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            NoSuchPaddingException,
            FileNotFoundException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidParameterSpecException,
            InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        int option_select;

        startup();
        while (true) {
            option_select = mainMenu();
            switch (option_select) {
                case 1:
                    checkIntegrity();
                    break;
                case 2:
                    registerAccount();
                    break;
                case 3:
                    deleteAccount();
                    break;
                case 4:
                    changeAccount();
                    break;
                case 5:
                    getPassword();
                    break;
                case 6:
                    System.exit(0);
            }
        }
    }
}
