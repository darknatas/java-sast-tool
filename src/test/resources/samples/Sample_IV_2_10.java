package com.example.sample;
import java.security.*;
public class Sample_IV_2_10 {
    void vuln(byte[] data, PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(key);
        sig.update(data);
        byte[] signature = sig.sign();  // IV-2.10: 서명 검증 없이 사용
    }
}
