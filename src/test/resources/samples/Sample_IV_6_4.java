package com.example.sample;
public class Sample_IV_6_4 {
    private int[] data;
    public void setData(int[] input) {
        this.data = input;  // IV-6.4: 방어적 복사 없이 직접 할당
    }
}
