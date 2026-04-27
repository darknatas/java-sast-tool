package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Sample_IV_1_13 {
    void vuln(HttpServletRequest req, HttpServletResponse resp) {
        String lang = req.getParameter("lang");
        resp.setHeader("Content-Language", lang);
    }
}
