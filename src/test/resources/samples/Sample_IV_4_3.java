package com.example.sample;
public class Sample_IV_4_3 {
    void vuln() {
        try {
            riskyOperation();
        } catch (Exception e) {  // IV-4.3: 너무 넓은 예외 타입 사용
            handleError(e);
        }
    }
    private void riskyOperation() throws Exception {}
    private void handleError(Exception e) {}
}
