package com.example.sample;
import java.io.PrintWriter;
import javax.servlet.http.*;
public class Sample_DS_1_5 {
    void vuln(HttpServletRequest req, HttpServletResponse response) throws Exception {
        String name = req.getParameter("name");
        PrintWriter out = response.getWriter();
        out.print(name);  // DS-1.5: XSS 인코딩 미적용
    }
}
