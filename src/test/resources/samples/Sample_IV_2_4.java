package com.example.sample;
import javax.crypto.*;
public class Sample_IV_2_4 {
    void vuln(byte[] data, javax.crypto.spec.SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);  // IV-2.4: 취약한 DES 알고리즘
        cipher.doFinal(data);
    }
}
