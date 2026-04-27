package com.example.sample;
import java.util.Random;
public class Sample_IV_2_8 {
    String generateToken() {
        Random rng = new Random();  // IV-2.8: 예측 가능한 난수
        return Integer.toHexString(rng.nextInt());
    }
}
