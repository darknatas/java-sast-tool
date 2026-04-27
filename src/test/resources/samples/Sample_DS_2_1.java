package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_2_1 {
    void processRequest(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        performSensitiveAction();  // DS-2.1: 인증 상태 확인 없이 실행
    }
    private void performSensitiveAction() {}
}
