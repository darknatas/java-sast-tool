package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_2_5 {
    void vuln(HttpServletRequest req) {
        String password = req.getParameter("password");  // IV-2.5: 평문 비밀번호 처리
        storeUser("admin", password);
    }
    private void storeUser(String u, String p) {}
}
