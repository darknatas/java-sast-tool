package com.example.sample;
public class Sample_IV_2_2 {
    private String userRole = "user";
    boolean isAdmin() { return "admin".equals(userRole); }
    void sensitiveAction() {
        if (isAdmin()) {  // IV-2.2: 서버 권한 검증 미흡
            deleteAllData();
        }
    }
    private void deleteAllData() {}
}
