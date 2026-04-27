package com.example.sample;
public class Sample_IV_7_2 {
    void vuln(String cmd) throws Exception {
        Runtime.exec(cmd);  // IV-7.2: 취약한 API 직접 사용
    }
}
