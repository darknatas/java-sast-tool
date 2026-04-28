package com.example.sample;
import javax.servlet.http.HttpSession;
public class Sample_DS_4_1 {
    // DS-4.1: 서비스 클래스 메서드가 HttpSession 객체를 직접 파라미터로 받는 취약 패턴
    public void setMemberInfo(HttpSession session, String userId) {
        session.setAttribute("user", userId);
    }
}
