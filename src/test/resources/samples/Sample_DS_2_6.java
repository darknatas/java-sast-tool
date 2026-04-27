package com.example.sample;
import javax.crypto.*;
import java.security.*;
public class Sample_DS_2_6 {
    void vuln(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("MD5");  // DS-2.6: 취약 알고리즘
    }
}
