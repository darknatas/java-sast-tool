package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_1_11 extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        // IV-1.11: CSRF 토큰 검증 없이 중요기능 처리
        String action = req.getParameter("action");
        executeAction(action);
    }
    private void executeAction(String a) {}
}
