package com.example.sample;
import java.io.*;
public class Sample_IV_5_2 {
    void vuln(File file) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        int data = fis.read();  // IV-5.2: try-with-resources 미사용
    }
}
