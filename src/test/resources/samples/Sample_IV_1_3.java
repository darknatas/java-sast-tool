package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
public class Sample_IV_1_3 {
    void vuln(HttpServletRequest req) throws Exception {
        String path = req.getParameter("file");
        File f = new File(path);  // IV-1.3: 경로조작 — 외부 입력으로 파일 경로 직접 생성
    }
}
