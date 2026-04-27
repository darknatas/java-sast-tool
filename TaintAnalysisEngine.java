package com.sast.engine.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.types.ResolvedType;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;

import java.util.*;

/**
 * Taint Analysis Engine
 *
 * Source → Propagator → Sink 흐름을 추적하여 보안약점을 탐지합니다.
 *
 * 분석 대상 약점 (가이드 PART4):
 *   - IV-1.1 SQL 삽입        (CWE-89)
 *   - IV-1.3 경로 조작 및 자원 삽입 (CWE-22, CWE-99)
 *   - IV-1.4 크로스사이트 스크립트  (CWE-79)
 *   - IV-1.5 운영체제 명령어 삽입   (CWE-78)
 *   (규칙 파일에 taintAnalysis: true인 항목 전체)
 *
 * 알고리즘: 인트라-프로시저럴 Dataflow (메서드 단위)
 *   1. Source 식별  - 외부 입력 API 호출 탐지
 *   2. Propagation  - 오염된 값이 대입되는 변수를 TaintSet에 누적
 *   3. Sanitizer    - 필터링/인코딩 메서드 호출 시 TaintSet에서 제거
 *   4. Sink 탐지    - TaintSet의 변수가 위험 API의 인자로 사용되면 취약점 보고
 */
public class TaintAnalysisEngine {

    // ── Source Signatures ────────────────────────────────────────────────

    /** 외부 입력 진입점 — 반환값이 오염 데이터 */
    private static final Set<String> SOURCE_METHODS = Set.of(
            // HTTP 요청 파라미터
            "getParameter", "getAttribute", "getQueryString",
            "getHeader", "getCookies", "getInputStream", "getReader",
            // 커맨드라인 인자
            "args",
            // 환경 변수 / 시스템 속성
            "getenv", "getProperty",
            // 파일 읽기
            "readLine", "readAllBytes",
            // 역직렬화 (IV-5.5)
            "readObject", "readUnshared"
    );

    // ── Sanitizer Signatures ─────────────────────────────────────────────

    /**
     * 오염 제거 메서드 — 이 메서드의 반환값은 안전한 것으로 간주
     * 주의: replaceAll 단독으로는 불충분할 수 있으나 sanitizer 체인 내 포함 시 허용
     */
    private static final Set<String> SANITIZER_METHODS = Set.of(
            // SQL
            "prepareStatement", "setString", "setInt", "setLong", "setObject",
            "setParameter", "escapeSQL",
            // XSS
            "escapeHtml", "encodeForHTML", "htmlEscape", "encodeHTML",
            // Path
            "getCanonicalPath", "normalize",
            // 공통 필터링
            "encodeForLDAP", "encodeForXPath", "encodeForHTTP",
            // ESAPI
            "encode", "canonicalize",
            // Spring
            "HtmlUtils.htmlEscape"
    );

    // ── Sink Signatures (Rule별 매핑) ─────────────────────────────────────

    /** ruleId → Sink 메서드 이름 목록 */
    private static final Map<String, Set<String>> RULE_SINKS = Map.of(
            "IV-1.1", Set.of("executeQuery", "executeUpdate", "execute",
                             "executeBatch", "createNativeQuery", "createQuery"),
            "IV-1.3", Set.of("new File", "new FileInputStream", "new FileOutputStream",
                             "new FileReader", "Paths.get", "new URL",
                             "openConnection", "new ServerSocket", "new Socket"),
            "IV-1.4", Set.of("print", "println", "write", "getWriter",
                             "sendRedirect"),
            "IV-1.5", Set.of("exec", "ProcessBuilder", "command"),
            "IV-1.9", Set.of("evaluate", "executeXPath", "compile"),
            "IV-1.10", Set.of("search", "InitialDirContext"),
            "IV-1.12", Set.of("new URL", "openConnection", "getForObject",
                              "exchange"),
            "IV-1.13", Set.of("setHeader", "addHeader"),
            "IV-1.17", Set.of("format", "printf", "MessageFormat.format"),
            "IV-5.5",  Set.of("readObject", "readUnshared")
    );

    // ── State per method analysis ─────────────────────────────────────────

    /**
     * 변수 이름 → 오염 경로 정보
     * 메서드 분석마다 초기화됩니다.
     */
    private final Map<String, TaintInfo> taintSet = new LinkedHashMap<>();

    private final List<Finding> findings = new ArrayList<>();
    private String currentFile;
    private SecurityRule currentRule;

    // ────────────────────────────────────────────────────────────────────
    // Public API
    // ────────────────────────────────────────────────────────────────────

    /**
     * CompilationUnit 전체를 분석하여 발견된 취약점 목록을 반환합니다.
     *
     * @param cu       JavaParser로 파싱된 AST
     * @param filePath 분석 중인 Java 파일 경로
     * @param rules    적용할 보안 규칙 목록
     */
    public List<Finding> analyze(CompilationUnit cu, String filePath, List<SecurityRule> rules) {
        this.currentFile = filePath;
        findings.clear();

        // 각 규칙에 대해 메서드별 Taint 분석 수행
        for (SecurityRule rule : rules) {
            if (!rule.isTaintAnalysis()) continue;
            this.currentRule = rule;

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                taintSet.clear();
                method.accept(new TaintVisitor(), null);
            });
        }
        return Collections.unmodifiableList(findings);
    }

    // ────────────────────────────────────────────────────────────────────
    // AST Visitor: 메서드 내 Dataflow 분석
    // ────────────────────────────────────────────────────────────────────

    private class TaintVisitor extends VoidVisitorAdapter<Void> {

        /**
         * 변수 선언 처리:
         *   String userId = request.getParameter("id");  ← Source 탐지
         *   String safe  = userId.replaceAll(...)        ← Sanitizer 탐지
         */
        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);

            if (n.getInitializer().isEmpty()) return;
            Expression init = n.getInitializer().get();

            String varName = n.getNameAsString();
            int    line    = n.getBegin().map(p -> p.line).orElse(-1);

            // Case 1: Source 메서드 호출 결과를 변수에 대입
            if (isSourceCall(init)) {
                taintSet.put(varName, new TaintInfo(
                        init.toString(), line, new ArrayList<>()
                ));
                return;
            }

            // Case 2: 오염된 변수가 포함된 표현식으로 초기화 (전파)
            if (isTainted(init)) {
                List<String> propagators = collectTaintedVars(init);
                TaintInfo    origin      = taintSet.get(propagators.get(0));
                taintSet.put(varName, new TaintInfo(
                        origin != null ? origin.sourceExpr : init.toString(),
                        origin != null ? origin.sourceLine : line,
                        propagators
                ));
                return;
            }

            // Case 3: Sanitizer 결과를 대입하면 오염 제거
            if (isSanitizerCall(init) && taintSet.containsKey(varName)) {
                taintSet.remove(varName);
            }
        }

        /**
         * 대입문 처리:
         *   sql = "SELECT * FROM t WHERE id='" + userId + "'";
         */
        @Override
        public void visit(AssignExpr n, Void arg) {
            super.visit(n, arg);

            if (!(n.getTarget() instanceof NameExpr target)) return;
            String varName = target.getNameAsString();
            int    line    = n.getBegin().map(p -> p.line).orElse(-1);
            Expression val = n.getValue();

            if (isSourceCall(val)) {
                taintSet.put(varName, new TaintInfo(val.toString(), line, new ArrayList<>()));
            } else if (isTainted(val)) {
                List<String> propagators = collectTaintedVars(val);
                TaintInfo origin = propagators.isEmpty() ? null : taintSet.get(propagators.get(0));
                taintSet.put(varName, new TaintInfo(
                        origin != null ? origin.sourceExpr : val.toString(),
                        origin != null ? origin.sourceLine : line,
                        propagators
                ));
            } else if (isSanitizerCall(val)) {
                taintSet.remove(varName);
            }
        }

        /**
         * 메서드 호출문 처리:
         *   stmt.executeQuery(sql);   ← Sink 탐지
         *   pstmt.setString(1, val);  ← Sanitizer 체크
         */
        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);

            String methodName = n.getNameAsString();
            int    line       = n.getBegin().map(p -> p.line).orElse(-1);

            // ① Sink 탐지
            Set<String> sinks = RULE_SINKS.getOrDefault(currentRule.getRuleId(), Set.of());
            if (sinks.contains(methodName)) {
                n.getArguments().forEach(argExpr -> {
                    if (isTainted(argExpr)) {
                        String taintedVar = firstTaintedVar(argExpr);
                        TaintInfo info = taintSet.get(taintedVar);
                        reportFinding(
                                info,
                                taintedVar,
                                n.toString(),
                                line
                        );
                    }
                });
            }

            // ② Sanitizer — 메서드 호출 후 관련 변수 오염 제거
            if (SANITIZER_METHODS.contains(methodName)) {
                n.getArguments().forEach(argExpr -> {
                    if (argExpr instanceof NameExpr ne) {
                        taintSet.remove(ne.getNameAsString());
                    }
                });
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Helper Methods
    // ────────────────────────────────────────────────────────────────────

    /** 표현식이 Source API 호출인지 확인 */
    private boolean isSourceCall(Expression expr) {
        if (expr instanceof MethodCallExpr call) {
            return SOURCE_METHODS.contains(call.getNameAsString());
        }
        return false;
    }

    /** 표현식이 Sanitizer 호출인지 확인 */
    private boolean isSanitizerCall(Expression expr) {
        if (expr instanceof MethodCallExpr call) {
            return SANITIZER_METHODS.contains(call.getNameAsString());
        }
        return false;
    }

    /**
     * 표현식에 오염된 변수가 포함되어 있는지 재귀 확인
     * Binary(+), 메서드 인자, 조건식 등을 처리합니다.
     */
    private boolean isTainted(Expression expr) {
        if (expr instanceof NameExpr ne) {
            return taintSet.containsKey(ne.getNameAsString());
        }
        if (expr instanceof BinaryExpr be) {
            return isTainted(be.getLeft()) || isTainted(be.getRight());
        }
        if (expr instanceof MethodCallExpr call) {
            // 수신 객체 자체가 오염된 경우 (e.g., taintedStr.toLowerCase())
            boolean scopeTainted = call.getScope()
                    .filter(s -> s instanceof NameExpr ne && taintSet.containsKey(ne.getNameAsString()))
                    .isPresent();
            boolean argTainted = call.getArguments().stream().anyMatch(this::isTainted);
            return scopeTainted || argTainted;
        }
        if (expr instanceof EnclosedExpr ee) {
            return isTainted(ee.getInner());
        }
        if (expr instanceof CastExpr ce) {
            return isTainted(ce.getExpression());
        }
        return false;
    }

    /** 표현식에서 오염된 변수 이름 목록을 수집 */
    private List<String> collectTaintedVars(Expression expr) {
        List<String> result = new ArrayList<>();
        collectTaintedVarsRecursive(expr, result);
        return result;
    }

    private void collectTaintedVarsRecursive(Expression expr, List<String> out) {
        if (expr instanceof NameExpr ne && taintSet.containsKey(ne.getNameAsString())) {
            out.add(ne.getNameAsString());
        } else if (expr instanceof BinaryExpr be) {
            collectTaintedVarsRecursive(be.getLeft(), out);
            collectTaintedVarsRecursive(be.getRight(), out);
        } else if (expr instanceof MethodCallExpr call) {
            call.getScope().ifPresent(s -> collectTaintedVarsRecursive(s, out));
            call.getArguments().forEach(a -> collectTaintedVarsRecursive(a, out));
        }
    }

    /** 표현식에서 첫 번째 오염 변수 이름을 반환 */
    private String firstTaintedVar(Expression expr) {
        List<String> vars = collectTaintedVars(expr);
        return vars.isEmpty() ? "<unknown>" : vars.get(0);
    }

    /** 취약점 발견 보고 */
    private void reportFinding(TaintInfo info, String taintedVar,
                               String sinkExpr, int sinkLine) {
        String sourceExpr = info != null ? info.sourceExpr : "unknown";
        int    sourceLine = info != null ? info.sourceLine : -1;
        List<String> props = info != null ? info.propagators : List.of();

        Finding.TaintFlow flow = new Finding.TaintFlow(
                sourceExpr, sourceLine, props, sinkExpr, sinkLine
        );

        findings.add(Finding.builder()
                .ruleId(currentRule.getRuleId())
                .ruleName(currentRule.getName())
                .severity(Finding.Severity.valueOf(currentRule.getSeverity()))
                .filePath(currentFile)
                .lineNumber(sinkLine)
                .vulnerableCode(sinkExpr)
                .description(String.format(
                        "외부 입력값 '%s'(%s L%d)이 검증 없이 %s(L%d)에 사용됩니다.",
                        taintedVar, sourceExpr, sourceLine, sinkExpr, sinkLine))
                .taintFlows(List.of(flow))
                .guideRef(currentRule.getGuideRef())
                .cweIds(currentRule.getCweIds())
                .build());
    }

    // ────────────────────────────────────────────────────────────────────
    // Inner Data Class
    // ────────────────────────────────────────────────────────────────────

    /** 오염 변수에 대한 메타데이터 */
    private static class TaintInfo {
        final String       sourceExpr;  // 최초 Source 표현식
        final int          sourceLine;  // Source 라인 번호
        final List<String> propagators; // 중간 전파 변수 이름 목록

        TaintInfo(String sourceExpr, int sourceLine, List<String> propagators) {
            this.sourceExpr  = sourceExpr;
            this.sourceLine  = sourceLine;
            this.propagators = propagators;
        }
    }
}
