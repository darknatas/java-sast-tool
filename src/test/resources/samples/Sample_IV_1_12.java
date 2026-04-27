package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import java.net.*;
public class Sample_IV_1_12 {
    void vuln(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        URL    url    = new URL(target);
        url.openConnection();
    }
}
