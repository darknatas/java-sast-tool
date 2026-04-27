package com.example.sample;
import javax.servlet.http.HttpServletRequest;
public class Sample_IV_1_15 {
    void vuln(HttpServletRequest req) {
        String role = req.getParameter("role");
        if ("admin".equals(role)) {
            deleteAllRecords();
        }
    }
    private void deleteAllRecords() {}
}
