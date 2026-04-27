package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_6_1 {
    private static HttpSession sharedSession;  // IV-6.1: 스레드 간 세션 공유
    void setSession(HttpSession session) {
        sharedSession = session;
    }
}
