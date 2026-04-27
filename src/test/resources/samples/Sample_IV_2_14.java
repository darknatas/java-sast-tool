package com.example.sample;
import java.security.*;
public class Sample_IV_2_14 {
    byte[] vuln(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());  // IV-2.14: 솔트 없는 MD5 해시
    }
}
