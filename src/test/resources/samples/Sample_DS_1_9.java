package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_1_9 {
    void vuln(HttpServletRequest req, HttpSession session) {
        String role = req.getParameter("role");  // DS-1.9: 외부 입력으로 보안결정
        session.setAttribute("userRole", role);
    }
}
