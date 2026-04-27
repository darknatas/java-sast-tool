package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_2_1 extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        // IV-2.1: 인증 확인 없이 관리자 기능 실행
        executeAdminAction(req.getParameter("action"));
    }
    private void executeAdminAction(String a) {}
}
