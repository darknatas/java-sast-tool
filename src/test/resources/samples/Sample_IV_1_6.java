package com.example.sample;
import javax.servlet.http.*;
public class Sample_IV_1_6 {
    void vuln(HttpServletRequest req) throws Exception {
        Part filePart = req.getPart("file");  // IV-1.6: 파일 확장자 검증 없음
        String filename = filePart.getSubmittedFileName();
        filePart.write("/upload/" + filename);
    }
}
