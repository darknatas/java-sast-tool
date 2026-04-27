package com.example.sample;
public class Sample_IV_6_3 {
    private int[] sensitiveData = {1, 2, 3};
    public int[] getSensitiveData() {  // IV-6.3: private 배열 직접 반환
        return sensitiveData;
    }
}
