package com.example.sample;
import java.io.*;
public class Sample_IV_2_3 {
    void vuln(File sensitiveFile) {
        sensitiveFile.setReadable(true, false);  // IV-2.3: 전체 읽기 권한 부여
        sensitiveFile.setWritable(true, false);  // IV-2.3: 전체 쓰기 권한 부여
    }
}
