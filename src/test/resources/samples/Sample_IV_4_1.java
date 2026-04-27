package com.example.sample;
public class Sample_IV_4_1 {
    void vuln() {
        try {
            riskyOperation();
        } catch (Exception e) {
            e.printStackTrace();  // IV-4.1: 시스템 정보 노출
        }
    }
    private void riskyOperation() throws Exception {}
}
