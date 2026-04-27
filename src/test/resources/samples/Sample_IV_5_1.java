package com.example.sample;
import java.util.Optional;
public class Sample_IV_5_1 {
    void vuln(Optional<String> optional) {
        String value = optional.get().trim();  // IV-5.1: null 체크 없이 get() 사용
        System.out.println(value);
    }
}
