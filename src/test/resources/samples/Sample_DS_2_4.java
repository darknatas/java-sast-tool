package com.example.sample;
import java.io.*;
public class Sample_DS_2_4 {
    void vuln(File sensitiveFile) {
        sensitiveFile.setReadable(true, false);  // DS-2.4: 전체 읽기 허용
        sensitiveFile.setWritable(true, false);  // DS-2.4: 전체 쓰기 허용
    }
}
