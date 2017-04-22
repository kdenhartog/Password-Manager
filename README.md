This is a programming project that was designed for a computer security class at the University of Iowa. Design constraints can be found in the document titled "CS4640_PP1.pdf".

## Compile
To compile:
./compile.sh

To run:
./run.sh

Note: both of these scripts have been given executable permissions, but if you have issues with the above command you should try:
chmod +x run.sh
or
chmod +x compile.sh

## Design Decisions

We chose to break the files up into two classes to handle this project. SecurityFunction is a class containing the functions used for all security functions such as Hmac(HmacSHA512), hashing(SHA-512), Encryption(AES-128), Decryption(AES-128), and randomNumberGenerator(salt generator). Additionally

All functions in SecurityFunction except generateKey take in input and return outputs. These functions all require the use of a Key generated from the master_passwd file which is guaranteed secure through other means as per the requirement documents. This Key generateKey function is private to ensure that it can only be used by functions contained in the SecurityFunction class.

In the main class called PassManager we performed all security functions required by the constraints. These were:
    1.) Which accounts you have registered for
    2.) Usernames of any of the accounts you have registered for
    3.) Passwords of any registered accounts

These guarantees are met by encrypting all data in the passwd_file after any changes are made to the data in this file. Additionally a new IV is generated using a SecureRandom object (which is considered FIPS compliant) each time the sensitive data is encrypted. This IV is stored in front of the data in plaintext (byte[]) so that it can be reused by the decrypt function. Additionally at the end of encryption a new Hmac is generated of the (IV, encrypted data) tuple and appended on. The storage format of passwd_file follows (Hmac (64 bytes), IV (128 bytes), encrypted data(as needed)) All of this data is then stored in the passwd_file ensuring Confidentiality and Integrity of the 3 constraints listed above.

Additionally these functions have been given private access modifiers so that they are only accessible through the calls of a function called mainMenu which is only accessible from within the class. In the main class that runs this program mainMenu is called only after the startup function completes. In startup a call is made to passwordCheck which is used for master password authentication. This uses a hash stored from the master password provided at setup with a salt, and compares it to the entered password combined with the salt taken from master_passwd. This test is performed at most 5 times. This is to prevent the use of a brute force attack on the the master password to break in. Once authenticated the startup function generates a private key that is accessible only by the functions contained within the same class by using a private access modifier. Furthermore this key is only useable within this session as it is stored as a program variable and dumped when the program has been shutdown. This key is generated using the master password that is entered for authentication.
