package com.example.sample;
public class Sample_IV_1_16 {
    void vuln(byte[] src, int userOffset, int userLength) {
        byte[] dst = new byte[1024];
        System.arraycopy(src, userOffset, dst, 0, userLength);
    }
}
