package com.example.dao;

import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.Arrays;
import java.util.List;

/**
 * 전자정부 프레임워크 스타일 DAO — 게시판 다중 조건 동적 검색
 *
 * 실제 금융·공공기관 레거시 시스템에서 자주 발견되는 패턴:
 *   - 검색 컬럼명을 사용자 파라미터로 동적 선택 → 컬럼 인젝션
 *   - 다단계 WHERE 절을 String 연결로 조합 → SQL 인젝션
 *   - 페이지네이션 파라미터 미검증 → LIMIT 인젝션
 *
 * 기술부채: PreparedStatement 전환 업무 미할당 (JIRA: LEGACY-2041)
 */
public class Complex_IV_1_1 {

    private static final List<String> ALLOWED_COLUMNS =
            Arrays.asList("title", "content", "writer_nm", "reg_dt");

    private static final String TBL_BOARD = "TB_BBS_BOARD";
    private static final String TBL_USER  = "TB_USER_INFO";

    /**
     * 다중 조건 게시글 목록 조회 — 4개 외부 파라미터가 SQL로 직접 삽입
     *
     * 취약 지점:
     *   [1] srchType → 컬럼명 직접 사용 (column injection)
     *   [2] srchWord → LIKE 절 삽입 (SQL injection)
     *   [3] deptCd   → WHERE 조건 삽입 (SQL injection)
     *   [4] pageSize → LIMIT 절 삽입 (numeric injection)
     */
    public ResultSet searchBoardList(HttpServletRequest request, Connection conn) throws Exception {

        // ① Source — 검색 조건 파라미터 (4개 외부 입력)
        String srchType = request.getParameter("srchType");  // "title" | "content" | "writer_nm"
        String srchWord = request.getParameter("srchWord");  // 검색 키워드 (예: "예산" 또는 "' OR 1=1--")
        String deptCd   = request.getParameter("deptCd");   // 부서 코드 (예: "1001" 또는 "'; DROP TABLE--")
        String pageSize = request.getParameter("pageSize"); // 페이지 크기 (예: "10" 또는 "10 UNION SELECT...")

        // ② Propagation 1단계 — 컬럼명 동적 선택 (allowlist 체크하지만 srchType 자체가 오염됨)
        String searchCol;
        if (ALLOWED_COLUMNS.contains(srchType)) {
            searchCol = "B." + srchType;   // taint: srchType이 allowlist 통과해도 concat으로 오염 전파
        } else {
            searchCol = "B.title";
        }

        // ③ Propagation 2단계 — LIKE 절 조합 (srchWord 직접 삽입)
        String likeFilter = searchCol + " LIKE '%" + srchWord + "%'";   // taint: searchCol(←srchType), srchWord

        // ④ Propagation 3단계 — 부서 조건 조합 (deptCd 직접 삽입)
        String deptFilter = "B.DEPT_CD = '" + deptCd + "'";             // taint: deptCd

        // ⑤ Propagation 4단계 — 전체 WHERE 절 결합
        String whereClause = likeFilter + " AND " + deptFilter          // taint: likeFilter + deptFilter
                           + " AND B.DEL_YN = 'N'";

        // ⑥ Propagation 5단계 — JOIN 쿼리 + 페이지네이션 조합 (pageSize 직접 삽입)
        String joinSql = "SELECT B.POST_NO, B.TITLE, B.CONT, B.REG_DT,"
                       + "       U.USER_NM, U.DEPT_NM"
                       + " FROM " + TBL_BOARD + " B"
                       + " LEFT OUTER JOIN " + TBL_USER + " U"
                       + "   ON B.REG_ID = U.USER_ID"
                       + " WHERE " + whereClause;                        // taint propagation
        String finalSql = joinSql + " ORDER BY B.REG_DT DESC"
                        + " LIMIT " + pageSize;                          // taint: pageSize

        // ⑦ Sink — executeQuery에 완전 오염된 SQL 전달 (IV-1.1 탐지)
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(finalSql);   // SINK: IV-1.1 SQL 삽입
    }
}
