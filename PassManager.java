package passwordmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Scanner;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author kyle
 */
public class PassManager {

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

    private static void check_integrity() {
        System.out.println("Checking Integrity...\n");
    }

    private static void register_account() {
        System.out.println("Registering Account...\n");
    }

    private static void delete_account() {
        System.out.println("Deleting Account...\n");
    }

    private static void change_account() {
        System.out.println("Changing Account...\n");
    }

    private static void get_password() {
        System.out.println("Getting Your Password...\n");
    }

    private static void setup() throws NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {
        
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
        } catch (Exception e) {
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

    private static boolean password_check(String entry) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
 
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

    private static boolean file_check() {
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

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        String master_passwd;
        Scanner sc = new Scanner(System.in);
        int option_select;

        System.out.println("\nWelcome to your password manager");

        if (!file_check()) {
            setup();
        } else {
            System.out.print("\nPlease enter your master password: ");
            while (!sc.hasNext()){
                System.out.print("\nPlease enter your master password: ");
            }
            master_passwd = sc.next();
            
            //verifies password are correct or exits after 5 attempts
            int counter = 0;
            while (!password_check(master_passwd)) {
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

        while (true) {
            option_select = mainMenu();

            switch (option_select) {
                case 1:
                    check_integrity();
                    break;
                case 2:
                    register_account();
                    break;
                case 3:
                    delete_account();
                    break;
                case 4:
                    change_account();
                    break;
                case 5:
                    get_password();
                    break;
                case 6:
                    System.exit(0);
            }
        }
    }
}