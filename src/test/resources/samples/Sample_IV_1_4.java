package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Sample_IV_1_4 {
    void vuln(HttpServletRequest req, PrintWriter out) {
        String name = req.getParameter("name");
        out.println(name);
    }
}
