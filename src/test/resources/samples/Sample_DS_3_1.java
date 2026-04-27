package com.example.sample;
public class Sample_DS_3_1 {
    void vuln() {
        try {
            int x = Integer.parseInt("abc");
        } catch (NumberFormatException e) {  // DS-3.1: 예외 정보 노출
            e.printStackTrace();
        }
    }
}
