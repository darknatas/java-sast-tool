package com.example.sample;
public class Sample_DS_1_8 {
    void vuln(byte[] src, int offset, int length) {
        byte[] dst = new byte[length];
        System.arraycopy(src, offset, dst, 0, length);  // DS-1.8: 경계 검사 없음
    }
}
