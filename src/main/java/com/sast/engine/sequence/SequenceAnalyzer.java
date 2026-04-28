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

    // TOCTOU Use 단계: 파일 객체를 scope로 사용/변경하는 메서드들 (IV-3.1)
    private static final Set<String> USE_METHODS = Set.of(
            "delete", "renameTo", "createNewFile", "mkdir", "mkdirs", "write", "transferTo"
    );

    // TOCTOU Use 단계: 파일 객체를 인자(argument)로 받아 사용하는 정적/유틸 메서드들 (IV-3.1)
    // 예: FileUtils.readFileToByteArray(file) — scope는 FileUtils이지만 file이 인자
    private static final Set<String> USE_ARG_METHODS = Set.of(
            // Apache Commons IO
            "readFileToByteArray", "readFileToString", "readLines",
            "copyFile", "copyFileToDirectory", "moveFile", "moveFileToDirectory",
            "deleteQuietly", "forceDelete", "writeByteArrayToFile",
            // java.nio.file.Files (static)
            "readAllBytes", "readString", "readAllLines",
            "copy", "move", "deleteIfExists",
            "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter"
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

        // ── 스코프(scope) 기반 탐지 ───────────────────────────────────────
        // file.exists() → [중간에 file.isFile() 등이 있어도] → file.delete() 패턴
        if (target != null) {
            if (CHECK_METHODS.contains(methodName)) {
                // Check 단계: 변수에 검사 호출 기록 (이전 check 항목을 덮어씀)
                // exists() 이후 isFile() 호출도 check로 등록 → 이후 delete() 탐지 유지
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

        // ── 인자(argument) 기반 탐지 ─────────────────────────────────────
        // FileUtils.readFileToByteArray(file) 처럼 file을 인자로 받는 유틸 메서드 패턴
        // scope는 FileUtils이지만, checked 변수가 인자로 전달되면 TOCTOU
        if (USE_ARG_METHODS.contains(methodName)) {
            for (Expression arg : call.getArguments()) {
                if (arg instanceof NameExpr ne) {
                    String varName = ne.getNameAsString();
                    CheckInfo check = checkMap.get(varName);
                    if (check != null) {
                        String key = varName + ":" + check.line + ":" + line + ":arg";
                        if (reported.add(key)) {
                            findings.add(buildFinding(rule, filePath, check, varName,
                                    call.toString(), line));
                        }
                    }
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
