package com.example.sample;
import java.security.*;
public class Sample_IV_2_7 {
    void vuln() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);  // IV-2.7: RSA 512비트는 취약한 키 길이
        KeyPair keyPair = kpg.generateKeyPair();
    }
}
