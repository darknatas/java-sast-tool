package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
public class Sample_IV_1_15 {
    void vuln(HttpServletRequest req, HttpSession session) {
        String role = req.getParameter("role");
        session.setAttribute("userRole", role);  // IV-1.15: 보안기능 결정에 사용자 입력 직접 사용
    }
}
