package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_2_7 {
    void vuln(HttpServletResponse resp, String userId) {
        Cookie cookie = new Cookie("userId", userId);  // DS-2.7: 보안속성 미설정
        resp.addCookie(cookie);
    }
}
