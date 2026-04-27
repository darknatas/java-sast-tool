package com.example.sample;
import java.net.*;
public class Sample_DS_2_8 {
    void vuln() throws Exception {
        HttpURLConnection conn = (HttpURLConnection)
            new URL("http://api.example.com/data").openConnection();
        conn.setRequestMethod("POST");  // DS-2.8: 평문 전송
    }
}
