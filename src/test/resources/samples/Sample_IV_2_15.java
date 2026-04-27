package com.example.sample;
import java.net.*;
import java.io.*;
public class Sample_IV_2_15 {
    void vuln(String url) throws Exception {
        InputStream in = new URL(url).openStream();  // IV-2.15: 체크섬 검증 없음
        byte[] data = in.readAllBytes();
    }
}
