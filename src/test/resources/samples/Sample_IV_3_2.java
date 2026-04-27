package com.example.sample;
public class Sample_IV_3_2 {
    void vuln() {
        while (true) {  // IV-3.2: 종료 조건 없는 무한루프
            processNext();
        }
    }
    private void processNext() {}
}
