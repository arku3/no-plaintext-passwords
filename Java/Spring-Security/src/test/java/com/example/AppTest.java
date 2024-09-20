package com.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class AppTest {

    @Test
    public void testArgon2() {
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
        PasswordEncoder encoder = new Argon2PasswordEncoder(
                16, // salt length
                32, // hash length
                1, // parallelism
                19456, // memory
                2 // iterations
        );
        String hash = encoder.encode("INPUT_PASSWORD");
        System.out.println(hash);

        assertTrue(encoder.matches("INPUT_PASSWORD", hash));  // true        
        assertFalse(encoder.matches("BAD_PASSWORD", hash)); // false
    }

    @Test
    public void testBCrypt() {
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#bcrypt
        PasswordEncoder encoder = new BCryptPasswordEncoder(12); // cost, Default is 10
        String hash = encoder.encode("INPUT_PASSWORD");
        System.out.println(hash);

        assertTrue(encoder.matches("INPUT_PASSWORD", hash));  // true        
        assertFalse(encoder.matches("BAD_PASSWORD", hash)); // false
    }

    @Test
    public void testSCrypt() {
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
        PasswordEncoder encoder = new SCryptPasswordEncoder(
                32768, // N=2^15 (32MiB). Default is 65536
                8, // r=8 (1024 bytes). Default is 8
                3, // p=3. Default is 1
                32, // salt length
                64 // hash length     
        );
        String hash = encoder.encode("INPUT_PASSWORD");
        System.out.println(hash);

        assertTrue(encoder.matches("INPUT_PASSWORD", hash));  // true        
        assertFalse(encoder.matches("BAD_PASSWORD", hash)); // false
    }
}
