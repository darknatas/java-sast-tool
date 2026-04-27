package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_2_12 {
    void vuln(HttpServletResponse resp, String sessionId) {
        Cookie cookie = new Cookie("JSESSIONID", sessionId);
        // IV-2.12: HttpOnly/Secure 속성 미설정
        resp.addCookie(cookie);
    }
}
