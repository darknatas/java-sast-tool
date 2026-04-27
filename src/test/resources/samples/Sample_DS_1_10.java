package com.example.sample;
import javax.servlet.http.*;
public class Sample_DS_1_10 {
    void vuln(HttpServletRequest req) throws Exception {
        Part part = req.getPart("file");  // DS-1.10: 파일 검증 미설계
        part.write("/upload/" + part.getSubmittedFileName());
    }
}
