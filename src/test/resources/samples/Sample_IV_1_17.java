package com.example.sample;
import javax.servlet.http.HttpServletRequest;
public class Sample_IV_1_17 {
    void vuln(HttpServletRequest req) {
        String fmt    = req.getParameter("format");
        String result = String.format(fmt, "arg");
        System.out.println(result);
    }
}
