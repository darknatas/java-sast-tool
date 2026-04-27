package com.example.sample;
import javax.servlet.http.HttpServletRequest;
public class Sample_IV_1_5 {
    void vuln(HttpServletRequest req) throws Exception {
        String cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
