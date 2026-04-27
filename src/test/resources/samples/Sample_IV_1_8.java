package com.example.sample;
import javax.xml.parsers.*;
import java.io.*;
public class Sample_IV_1_8 {
    void vuln(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // IV-1.8: 외부 엔티티 비활성화 없음
        factory.newDocumentBuilder().parse(input);
    }
}
