package com.example.sample;
public class Sample_IV_2_9 {
    boolean isValidPassword(String password) {
        if (password.length() < 4) {  // IV-2.9: 최소 길이 너무 짧음
            return false;
        }
        return true;
    }
}
