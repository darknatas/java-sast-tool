package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.sql.*;

/**
 * 오탐(False Positive) 감소 검증용 샘플.
 *
 * 이 파일의 모든 패턴은 정상 코드이므로 Finding이 0건이어야 한다.
 *
 * 검증 시나리오:
 *   [FP-1] escapeHtml 결과를 변수에 대입 후 출력 → XSS 오탐 방지
 *   [FP-2] PreparedStatement 사용 → SQL 오탐 방지
 *   [FP-3] System.out.println → XSS Sink 제외
 *   [FP-4] getCanonicalPath → 경로조작 오탐 방지
 *   [FP-5] 삼항 연산자 sanitizer 분기 → ConditionalExpr 처리
 */
public class FP_Sanitizer_Scenarios {

    // [FP-1] escapeHtml로 변수에 대입 후 응답 출력 — Finding 없어야 함
    public void safeXssOutput(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String raw = req.getParameter("comment");
        String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml4(raw);
        PrintWriter out = res.getWriter();
        out.println(safe);                          // safe 변수이므로 Finding 없음
    }

    // [FP-2] PreparedStatement 사용 — Finding 없어야 함
    public void safeSql(HttpServletRequest req, Connection conn) throws Exception {
        String userId = req.getParameter("userId");
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, userId);
        pstmt.executeQuery();                       // pstmt는 파라미터화 → Finding 없음
    }

    // [FP-3] System.out.println — XSS Sink 아님
    public void systemOutPrint(HttpServletRequest req) {
        String val = req.getParameter("debug");
        System.out.println(val);                    // 시스템 로그 출력 — Finding 없음
        System.err.println(val);                    // 시스템 에러 로그 — Finding 없음
    }

    // [FP-4] getCanonicalPath 경로 정규화 — Finding 없어야 함
    public void safePath(HttpServletRequest req) throws Exception {
        String fileName = req.getParameter("file");
        java.io.File base = new java.io.File("/var/data");
        java.io.File resolved = new java.io.File(base, fileName);
        String canonical = resolved.getCanonicalPath();
        java.io.File safeFile = new java.io.File(canonical); // canonical은 정규화됨 → Finding 없음
    }

    // [FP-5] 삼항 연산자에서 sanitizer 분기 — Finding 없어야 함
    public void conditionalSanitize(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String raw = req.getParameter("name");
        String safe = (raw != null) ? escapeHtml(raw) : "";  // sanitizer 결과
        res.getWriter().println(safe);              // safe → Finding 없음
    }

    // 프로젝트 내부 sanitizer 메서드
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
