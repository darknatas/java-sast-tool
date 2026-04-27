package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_1_14 {
    void vuln(HttpServletRequest req) {
        int size = Integer.parseInt(req.getParameter("size"));
        byte[] buffer = new byte[size * 2];  // IV-1.14: 오버플로우 검사 없음
    }
}
