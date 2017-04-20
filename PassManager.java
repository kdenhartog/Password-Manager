package passwordmanager;

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
import java.security.spec.InvalidParameterSpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author Kyle Den Hartog, Nicholas Kao, and Doug Ives
 */
public class PassManager {

    private static void checkIntegrity() {
        System.out.println("Checking Integrity...\n");
        //TODO: need plan of attack
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
            InvalidAlgorithmParameterException {
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

        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";

        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);
        byte[] encrypted;
        if (data.length > 0) {
            byte[] decrypted = SecurityFunction.decrypt(data);
            String account = domain + " " + username + " " + password + "!";

            if (accountLookup(domain, username, decrypted) == null) {
                byte[] dataBytes = account.getBytes("UTF-8");
                byte[] newData = Arrays.concatenate(decrypted, dataBytes);
                encrypted = SecurityFunction.encrypt(newData);
                //write to file       
                try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                    output.write(encrypted);
                    output.close();
                    System.out.println("USER ACCOUNT REGISTERED!\n");
                }
            } else {
                System.out.println("USER ACCOUNT ALREADY EXISTS!\n");
            }
        } else {
            String account = domain + " " + username + " " + password + "!";
            byte[] dataBytes = account.getBytes("UTF-8");
            encrypted = SecurityFunction.encrypt(dataBytes);
            //write to file
            try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                output.write(encrypted);
                output.close();
                System.out.println("USER ACCOUNT REGISTERED!\n");
            }
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
            InvalidAlgorithmParameterException {
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
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";

        Path path = Paths.get(passwd_file_path);
        byte[] data = Files.readAllBytes(path);
        byte[] encrypted;
        if (data.length > 0) {
            byte[] decrypted = SecurityFunction.decrypt(data);
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
                String newAccList = null;
                for (int i = 0; i < accounts.length; i++) {
                    if (accounts[i] != null) {
                        newAccList += accounts[i] + "!";
                    }
                }
                System.out.println(newAccList);
                if (newAccList != null) {
                    byte[] bytesData = newAccList.getBytes("UTF-8");
                    //encrypt new data
                    encrypted = SecurityFunction.encrypt(bytesData);
                    //write to file       
                    try (FileOutputStream output = new FileOutputStream("passwd_file")) {
                        output.write(encrypted);
                        output.close();
                        System.out.println("USER ACCOUNT REMOVED!\n");
                    }
                } else {//all accounts have been removed
                    System.out.println("ALL ACCOUNTS DELETED!\n");
                }
            } else {//account not found
                System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
            }
        } else {//no data
            System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
        }
    }

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
            InvalidAlgorithmParameterException {
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
        byte[] accountInfo = Files.readAllBytes(path);
        byte[] decrypted = SecurityFunction.decrypt(accountInfo);

        //TODO: if account doesn't exists print USER ACCOUNT DOES NOT EXISTS!\n
        //TODO: else find account, update password
        //newData will be data with account info updated
        byte[] newData = null;

        byte[] encrypted = SecurityFunction.encrypt(newData);

        try (FileOutputStream output = new FileOutputStream("passwd_file")) {
            output.write(encrypted);
            output.close();
        }
    }

    private static void getPassword() {
        Scanner sc = new Scanner(System.in);

        System.out.print("\nPlease enter a domain: ");
        String domain = sc.next();

        //TODO: lookup account
        //TODO: if exists convert username and password to String print using proper format
        //TODO: else print USER ACCOUNT DOES NOT EXIST!\n
    }

    private static void setup() throws
            NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {
        Scanner sc = new Scanner(System.in);
        //create passwd_file path
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";

        //Used for master_passwd path
        String master_passwd_path = System.getProperty("user.dir");
        master_passwd_path += "/master_passwd";

        //initialize files
        File passwd_file = new File(passwd_file_path);
        File master_passwd_file = new File(master_passwd_path);

        //create files
        try {
            passwd_file.createNewFile();
            master_passwd_file.createNewFile();
        } catch (IOException e) {
            System.out.println(e);
        }

        //get master password
        System.out.print("\nPlease provide a master password: ");
        String master_passwd = sc.next();
        byte[] password = master_passwd.getBytes();

        //get salt and combine with master password
        byte[] salt = SecurityFunction.randomNumberGenerator(256);
        byte[] salted_password = Arrays.concatenate(salt, password);

        byte[] hash = SecurityFunction.hash(salted_password);
        byte[] salt_and_hash = Arrays.concatenate(salt, hash);

        try (FileOutputStream output = new FileOutputStream("master_passwd")) {
            output.write(salt_and_hash);
        }

    }

    private static boolean passwordCheck(String entry) throws
            FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException {

        byte[] password = entry.getBytes();

        byte[] contents = new byte[320];

        try (FileInputStream input = new FileInputStream("master_passwd")) {
            //read in all 320 bytes from the master_passwd file
            for (int i = 0; i < 320; i++) {
                contents[i] = (byte) input.read();
            }
        }

        byte[] salt = Arrays.copyOf(contents, 256);

        //concatenate the salt and the password then hash it
        byte[] salted_password = Arrays.concatenate(salt, password);
        byte[] hashed = SecurityFunction.hash(salted_password);

        return (Arrays.areEqual(contents, Arrays.concatenate(salt, hashed)));

    }

    //This will be useful for making changes to acount/password lookup
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

    private static void startup() throws
            IOException,
            NoSuchAlgorithmException,
            FileNotFoundException,
            NoSuchProviderException {
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
            InvalidAlgorithmParameterException {
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
