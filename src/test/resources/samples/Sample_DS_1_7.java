package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_1_7 {
    void vuln(HttpServletRequest req, HttpServletResponse resp) {
        String lang = req.getParameter("lang");
        resp.setHeader("Content-Language", lang);  // DS-1.7: CRLF 필터 없음
    }
}
