package com.example.sample;
public class Sample_IV_2_16 {
    boolean authenticate(String user, String pass) {
        return checkDB(user, pass);  // IV-2.16: 로그인 시도 횟수 제한 없음
    }
    private boolean checkDB(String u, String p) { return false; }
}
