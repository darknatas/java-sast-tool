package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Sample_IV_1_7 {
    void vuln(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("redirect");
        resp.sendRedirect(url);
    }
}
