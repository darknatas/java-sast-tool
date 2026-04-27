package com.example.sample;
import java.io.*;
public class Sample_IV_5_3 {
    void vuln(File file) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        int first = fis.read();
        fis.close();   // IV-5.3: 자원 해제 후 재사용 위험
        int second = fis.read();
    }
}
