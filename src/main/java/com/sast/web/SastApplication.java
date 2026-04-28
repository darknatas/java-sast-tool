package com.sast.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// IV-1.6: 파일 업로드 보안 — MultipartProperties로 크기 제한 (application.properties)
// scanBasePackages: com.sast 전체 스캔 (report, filter 등 하위 패키지 포함)
@SpringBootApplication(scanBasePackages = "com.sast")
public class SastApplication {

    public static void main(String[] args) {
        SpringApplication.run(SastApplication.class, args);
    }
}
