package passwordmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Scanner;
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

    private static void registerAccount() {
        Scanner sc = new Scanner(System.in);
        //Get Domain Name
        while(!sc.hasNext()){
            System.out.print("\nPlease enter the domain name: ");
        }
        String domain = sc.next();

        //Get Username
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your username: ");
        }
        String username = sc.next();

        //Get password
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your password: ");
        }
        String password = sc.next();

        //TODO: if account already exists print USER ACCOUNT ALREADY EXISTS!\n
        //TODO: else add new account and re-encrypt entire passwd_file with new IV and master_pass as key

    }

    private static void deleteAccount() {
        Scanner sc = new Scanner(System.in);

        //Get Domain Name
        while(!sc.hasNext()){
            System.out.print("\nPlease enter the domain name: ");
        }
        String domain = sc.next();

        //Get Username
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your username: ");
        }
        String username = sc.next();

        //Get password
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your password: ");
        }
        String password = sc.next();

        //TODO: if account doesn't exists print USER ACCOUNT DOES NOT EXISTS!\n
        //TODO: else find account, remove account, and re-encrypt entire passwd_file with new IV and master_pass as key
    }

    private static void changeAccount() {
        Scanner sc = new Scanner(System.in);

        //Get Domain Name
        while(!sc.hasNext()){
            System.out.print("\nPlease enter the domain name: ");
        }
        String domain = sc.next();

        //Get Username
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your username: ");
        }
        String username = sc.next();

        //Get old password
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your password: ");
        }
        String oldpass = sc.next();

        //Get new password
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your password: ");
        }
        String newpass = sc.next();



        //TODO: if account doesn't exists print USER ACCOUNT DOES NOT EXISTS!\n
        //TODO: else find account, update password, and re-encrypt entire passwd_file with new IV and master_pass as key
    }

    private static void getPassword() {
        Scanner sc = new Scanner(System.in);

        //Get domain name
        while(!sc.hasNext()){
            System.out.print("\nPlease enter your password: ");
        }
        String domain = sc.next();

        //TODO: lookup account
        //TODO: if exists convert username and password to String print using proper format
        //TODO: else print USER ACCOUNT DOES NOT EXIST!\n
    }

    private static void setup() throws
    NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {
        //create passwd_file path
        String passwd_file_path = System.getProperty("user.dir");
        passwd_file_path += "/passwd_file";

        //Used for master_passwd path
        String master_passwd_path = System.getProperty("user.dir");
        master_passwd_path += "/master_passwd";

        File passwd_file = new File(passwd_file_path);
        File master_passwd_file = new File(master_passwd_path);

        try {
            passwd_file.createNewFile();
            master_passwd_file.createNewFile();
        } catch (IOException e) {
            System.out.println(e);
        }

        Scanner sc = new Scanner(System.in);

        String master_passwd;

        System.out.print("\nPlease provide a master password: ");
        while (!sc.hasNext()) {
            System.out.print("\nNo password enetered. Please provide a master password: ");
        }
        master_passwd = sc.next();

        byte[] password = master_passwd.getBytes();

        byte[] salt = SecurityFunction.saltGenerator();
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

    //This will be useful when needing to re-encrypt passwd_file
    private static String getMasterPass(){
        //TODO: Get master_passwd file,
        //TODO: pull the master_password from file
        //TODO: Convert from byte[] to String
        //TODO: return the String
        return "";
    }

    //This will be useful for making changes to acount/password lookup
    private static String accountLookup(String domain, String user, String pass){
        //TODO: return if account is in passwd_file given domain, user, and pass
        return "";
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
            IOException, NoSuchAlgorithmException, FileNotFoundException, 
            NoSuchProviderException {
        String master_passwd;
        Scanner sc = new Scanner(System.in);

        System.out.println("\nWelcome to your password manager");
        if (!fileCheck()) {
            setup();
        } else {
            System.out.print("\nPlease enter your master password: ");
            while (!sc.hasNext()){
                System.out.print("\nPlease enter your master password: ");
            }
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
        System.out.println("Please enter the number associated with the function "
        + "you would like to call.");
        System.out.println("1 - Check Integrity");
        System.out.println("2 - Register Account");
        System.out.println("3 - Delete Account");
        System.out.println("4 - Change Account");
        System.out.println("5 - Get Password");
        System.out.println("6 - Exit");

        int option = sc.nextInt();

        while (!(option >= 1 && option <= 6)) {
            System.out.println("Please enter an integer between 1 and 6: ");
            option = sc.nextInt();
        }

        return option;
    }

    public static void main(String[] args) throws
    NoSuchAlgorithmException, NoSuchProviderException, IOException {
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
