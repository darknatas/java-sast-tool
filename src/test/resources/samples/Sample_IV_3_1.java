package com.example.sample;
import java.io.*;
public class Sample_IV_3_1 {
    void vuln(File f) throws IOException {
        if (f.exists()) {
            FileInputStream fis = new FileInputStream(f);
            fis.close();
        }
    }
}
