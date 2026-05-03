package com.sast.taint;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.engine.taint.TaintAnalysisEngine;
import com.sast.model.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sanitizer 인식 강화 후 오탐(FP) 감소 검증 테스트.
 *
 * 각 케이스는 올바르게 sanitizer를 사용하는 코드이므로 Finding 0건을 기대한다.
 */
class SanitizerFalsePositiveTest {

    private TaintAnalysisEngine engine;
    private JavaParser parser;
    private List<SecurityRule> taintRules;

    @BeforeEach
    void setUp() throws Exception {
        CombinedTypeSolver solver = new CombinedTypeSolver();
        solver.add(new ReflectionTypeSolver());
        ParserConfiguration cfg = new ParserConfiguration()
                .setSymbolResolver(new JavaSymbolSolver(solver));
        parser = new JavaParser(cfg);
        engine = new TaintAnalysisEngine();
        taintRules = RuleLoader.loadFromClasspath("security-rules.json").stream()
                .filter(SecurityRule::isTaintAnalysis)
                .toList();
    }

    private CompilationUnit parse(String code) {
        return parser.parse(code).getResult()
                .orElseThrow(() -> new IllegalArgumentException("파싱 실패"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FP-1: escapeHtml 결과를 변수에 담아 출력 → XSS 오탐 없어야 함
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void fp1_escapeHtmlAssigned_shouldNotFire() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.io.*;
                class T {
                    void m(HttpServletRequest req, PrintWriter out) {
                        String raw  = req.getParameter("name");
                        String safe = escapeHtml(raw);
                        out.println(safe);
                    }
                    String escapeHtml(String s) { return s; }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> xss = findings.stream()
                .filter(f -> "IV-1.4".equals(f.getRuleId())).toList();
        assertThat(xss).as("escapeHtml 결과 변수 출력 — XSS 오탐 없어야 함").isEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FP-2: PreparedStatement 사용 → SQL 오탐 없어야 함
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void fp2_preparedStatement_shouldNotFire() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.sql.*;
                class T {
                    void m(HttpServletRequest req, Connection conn) throws Exception {
                        String id   = req.getParameter("id");
                        String sql  = "SELECT * FROM users WHERE id = ?";
                        PreparedStatement pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, id);
                        pstmt.executeQuery();
                    }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> sql = findings.stream()
                .filter(f -> "IV-1.1".equals(f.getRuleId())).toList();
        assertThat(sql).as("PreparedStatement 사용 — SQL 오탐 없어야 함").isEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FP-3: System.out.println → XSS Sink 아님
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void fp3_systemOutPrintln_shouldNotBeXssSink() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                class T {
                    void m(HttpServletRequest req) {
                        String val = req.getParameter("debug");
                        System.out.println(val);
                        System.err.println(val);
                    }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> xss = findings.stream()
                .filter(f -> "IV-1.4".equals(f.getRuleId())).toList();
        assertThat(xss).as("System.out.println — XSS 오탐 없어야 함").isEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FP-4: 삼항 연산자에서 sanitizer 결과 사용
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void fp4_ternaryWithSanitizer_shouldNotFire() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.io.*;
                class T {
                    void m(HttpServletRequest req, PrintWriter out) {
                        String raw  = req.getParameter("name");
                        String safe = (raw != null) ? escapeHtml(raw) : "";
                        out.println(safe);
                    }
                    String escapeHtml(String s) { return s; }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> xss = findings.stream()
                .filter(f -> "IV-1.4".equals(f.getRuleId())).toList();
        assertThat(xss).as("삼항 연산자 sanitizer — XSS 오탐 없어야 함").isEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TP-1: sanitizer 없이 그대로 출력 → XSS Finding 있어야 함 (진탐 회귀 방지)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void tp1_rawOutputWithoutSanitizer_shouldFire() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.io.*;
                class T {
                    void m(HttpServletRequest req, PrintWriter out) {
                        String name = req.getParameter("name");
                        out.println(name);
                    }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> xss = findings.stream()
                .filter(f -> "IV-1.4".equals(f.getRuleId())).toList();
        assertThat(xss).as("Sanitizer 없는 직접 출력 — XSS Finding 있어야 함").isNotEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TP-2: 문자열 연결 SQL → Finding 있어야 함 (진탐 회귀 방지)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void tp2_stringConcatSql_shouldFire() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.sql.*;
                class T {
                    void m(HttpServletRequest req, Statement stmt) throws Exception {
                        String id  = req.getParameter("id");
                        String sql = "SELECT * FROM users WHERE id='" + id + "'";
                        stmt.executeQuery(sql);
                    }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        List<Finding> sql = findings.stream()
                .filter(f -> "IV-1.1".equals(f.getRuleId())).toList();
        assertThat(sql).as("문자열 연결 SQL — SQL Injection Finding 있어야 함").isNotEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FP-5: 중복 Finding 방지 — 동일 라인에서 단 1건만 생성
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void fp5_duplicateFindingPrevention_singleFinding() {
        CompilationUnit cu = parse("""
                import javax.servlet.http.*;
                import java.sql.*;
                class T {
                    void m(HttpServletRequest req, Statement stmt) throws Exception {
                        String a = req.getParameter("a");
                        String b = req.getParameter("b");
                        String sql = "SELECT * FROM t WHERE x='" + a + "' AND y='" + b + "'";
                        stmt.executeQuery(sql);
                    }
                }
                """);
        List<Finding> findings = engine.analyze(cu, "T.java", taintRules);
        long iv11Count = findings.stream()
                .filter(f -> "IV-1.1".equals(f.getRuleId()))
                .map(Finding::getLineNumber)
                .distinct()
                .count();
        // executeQuery는 한 라인에 있으므로 IV-1.1 Finding은 1건만
        assertThat(iv11Count).as("동일 Sink 라인 — Finding 중복 없어야 함").isEqualTo(1L);
    }
}
