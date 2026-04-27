package com.example.sample;
public class Sample_DS_2_2 {
    private int loginAttempt = 0;  // DS-2.2: 횟수 제한 미설계
    boolean authenticate(String user, String pass) {
        loginAttempt++;
        return checkCredentials(user, pass);
    }
    private boolean checkCredentials(String u, String p) { return true; }
}
