package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_4_1 {
    void vuln(HttpServletRequest req) {
        HttpSession session = req.getSession(true);
        session.setMaxInactiveInterval(86400);  // DS-4.1: 세션 만료 미설계
    }
}
