package com.example.sample;
public class Sample_IV_4_2 {
    void vuln() {
        try {
            int x = 1 / 0;
        } catch (Exception e) {}
    }
}
