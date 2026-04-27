package com.example.sample;
public class Sample_DS_1_4 {
    void vuln(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);  // DS-1.4: OS 명령어 직접 실행
    }
}
