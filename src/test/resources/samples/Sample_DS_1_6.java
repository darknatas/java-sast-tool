package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_1_6 extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String amount = req.getParameter("amount");
        processTransfer(amount);  // DS-1.6: CSRF 토큰 검증 없음
    }
    private void processTransfer(String amount) {}
}
