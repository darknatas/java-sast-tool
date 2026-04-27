package com.example.sample;
import javax.crypto.*;
import javax.crypto.spec.*;
public class Sample_DS_2_5 {
    void vuln() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecretKey key = keyGen.generateKey();
        SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), "AES");
    }
}
