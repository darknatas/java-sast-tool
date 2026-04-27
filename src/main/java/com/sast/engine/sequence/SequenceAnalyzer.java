package com.sast.engine.sequence;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 시퀀스 분석 엔진 — 검사 시점과 사용 시점(TOCTOU) 탐지 (IV-3.1, CWE-367)
 *
 * 알고리즘: 메서드 단위 순차 탐지
 *   - Check 메서드(exists, canRead 등)가 호출된 변수에
 *   - 이후 Use 메서드(delete, new FileInputStream 등)가 호출되면 TOCTOU로 보고
 *
 * 두 연산 사이의 윈도우에서 다른 스레드/프로세스가 파일 상태를 변경할 수 있음.
 */
public class SequenceAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(SequenceAnalyzer.class);

    // TOCTOU Check 단계: 파일 상태를 검사하는 메서드들 (IV-3.1)
    private static final Set<String> CHECK_METHODS = Set.of(
            "exists", "canRead", "canWrite", "isFile", "isDirectory", "isReadOnly", "length"
    );

    // TOCTOU Use 단계: 파일을 실제로 사용/변경하는 메서드들 (IV-3.1)
    private static final Set<String> USE_METHODS = Set.of(
            "delete", "renameTo", "createNewFile", "mkdir", "mkdirs", "write", "transferTo"
    );

    // 파일을 여는 생성자 호출 — 이전에 checked된 변수를 인자로 받으면 TOCTOU
    private static final Set<String> FILE_OPEN_TYPES = Set.of(
            "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
            "RandomAccessFile", "PrintWriter"
    );

    public List<Finding> analyze(CompilationUnit cu, String filePath, SecurityRule rule) {
        List<Finding> findings = new ArrayList<>();
        Set<String> reported = new HashSet<>(); // dedup: varName:checkLine:useLine

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            // checkMap: 변수명 → 가장 최근 Check 정보 (메서드 단위 초기화)
            Map<String, CheckInfo> checkMap = new LinkedHashMap<>();

            // MethodCallExpr + ObjectCreationExpr 를 소스 라인 순서로 통합 처리
            List<ExprNode> ordered = new ArrayList<>();
            method.findAll(MethodCallExpr.class).forEach(c ->
                    ordered.add(new ExprNode(c.getBegin().map(p -> p.line).orElse(0), c, null)));
            method.findAll(ObjectCreationExpr.class).forEach(c ->
                    ordered.add(new ExprNode(c.getBegin().map(p -> p.line).orElse(0), null, c)));
            ordered.sort(Comparator.comparingInt(e -> e.line));

            for (ExprNode entry : ordered) {
                if (entry.methodCall != null) {
                    processMethodCall(entry.methodCall, checkMap, findings, reported, rule, filePath);
                } else if (entry.objectCreation != null) {
                    processObjectCreation(entry.objectCreation, checkMap, findings, reported, rule, filePath);
                }
            }
        });

        log.debug("[SequenceAnalyzer] {} — {}건 탐지", filePath, findings.size());
        return findings;
    }

    // ── 처리 메서드 ──────────────────────────────────────────────────────────

    private void processMethodCall(MethodCallExpr call, Map<String, CheckInfo> checkMap,
                                   List<Finding> findings, Set<String> reported,
                                   SecurityRule rule, String filePath) {
        String methodName = call.getNameAsString();
        int line = call.getBegin().map(p -> p.line).orElse(-1);
        String target = extractScopeTarget(call);
        if (target == null) return;

        if (CHECK_METHODS.contains(methodName)) {
            // Check 단계: 변수에 검사 호출 기록
            checkMap.put(target, new CheckInfo(methodName, line, call.toString()));
        } else if (USE_METHODS.contains(methodName)) {
            // Use 단계: 이전에 checked된 변수라면 TOCTOU
            CheckInfo check = checkMap.get(target);
            if (check != null) {
                String key = target + ":" + check.line + ":" + line;
                if (reported.add(key)) {
                    findings.add(buildFinding(rule, filePath, check, target, call.toString(), line));
                }
            }
        }
    }

    private void processObjectCreation(ObjectCreationExpr creation, Map<String, CheckInfo> checkMap,
                                       List<Finding> findings, Set<String> reported,
                                       SecurityRule rule, String filePath) {
        String typeName = creation.getTypeAsString();
        int line = creation.getBegin().map(p -> p.line).orElse(-1);
        if (!FILE_OPEN_TYPES.contains(typeName)) return;

        // new FileInputStream(f) 등: 인자로 받은 변수가 check 이후라면 TOCTOU
        for (Expression arg : creation.getArguments()) {
            if (arg instanceof NameExpr ne) {
                String varName = ne.getNameAsString();
                CheckInfo check = checkMap.get(varName);
                if (check != null) {
                    String key = varName + ":" + check.line + ":" + line;
                    if (reported.add(key)) {
                        findings.add(buildFinding(rule, filePath, check, varName,
                                "new " + typeName + "(" + varName + ")", line));
                    }
                }
            }
        }
    }

    // ── 헬퍼 ─────────────────────────────────────────────────────────────────

    private String extractScopeTarget(MethodCallExpr call) {
        return call.getScope()
                .filter(s -> s instanceof NameExpr)
                .map(s -> ((NameExpr) s).getNameAsString())
                .orElse(null);
    }

    private Finding buildFinding(SecurityRule rule, String filePath, CheckInfo check,
                                  String varName, String useExpr, int useLine) {
        String guideRef = (rule.getRemediation() != null) ? rule.getRemediation().getGuideRef() : "";
        return Finding.builder()
                .ruleId(rule.getRuleId())
                .ruleName(rule.getName())
                .severity(Finding.Severity.valueOf(rule.getSeverity()))
                .filePath(filePath)
                .lineNumber(useLine)
                .vulnerableCode(check.expr + "  →  " + useExpr)
                .description(String.format(
                        "파일 객체 '%s'에 대해 상태 검사(%s, L%d) 후 파일 사용(%s, L%d)이 발생합니다. " +
                        "두 연산 사이에 다른 스레드/프로세스가 파일 상태를 변경할 수 있습니다(TOCTOU).",
                        varName, check.method, check.line, useExpr, useLine))
                .taintFlows(Collections.emptyList())
                .guideRef(guideRef)
                .cweIds(rule.getCwe())
                .build();
    }

    // ── 내부 타입 ─────────────────────────────────────────────────────────────

    private record ExprNode(int line, MethodCallExpr methodCall, ObjectCreationExpr objectCreation) {}

    private static class CheckInfo {
        final String method;
        final int    line;
        final String expr;

        CheckInfo(String method, int line, String expr) {
            this.method = method;
            this.line   = line;
            this.expr   = expr;
        }
    }
}
