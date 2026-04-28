package com.sast;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.sast.engine.pattern.PatternAnalyzer;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.engine.sequence.SequenceAnalyzer;
import com.sast.engine.taint.TaintAnalysisEngine;
import com.sast.filter.FalsePositiveFilter;
import com.sast.filter.SuppressionLoader;
import com.sast.filter.SuppressionRule;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.report.PdfReportGenerator;
import com.sast.report.ReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Java SAST 진입점 — 전체 분석 파이프라인 조율
 *
 * 파이프라인:
 *   [1] Java 소스 파일 수집
 *   [2] JavaParser AST 파싱 (SymbolSolver 활성화)
 *   [3] security-rules.json 규칙 로드
 *   [4] TaintAnalysisEngine 오염 흐름 분석
 *   [5] SequenceAnalyzer TOCTOU 시퀀스 탐지
 *   [6] PatternAnalyzer 정규식 기반 탐지
 *   [7] FalsePositiveFilter 오탐 필터링
 *       - @SuppressWarnings("sast-ignore") 어노테이션 메서드 제외 (IV-6.2)
 *       - src/test/ 경로 위험도 하향
 *       - sast-suppressions.json 사용자 정의 억제
 *   [8] RemediationService 수정 코드 생성
 *   [9] ReportGenerator 리포트 출력 (MD + JSON + PDF)
 */
public class SASTEngine {

    private static final Logger log = LoggerFactory.getLogger(SASTEngine.class);

    private final JavaParser          parser;
    private final TaintAnalysisEngine taintEngine;
    private final PatternAnalyzer     patternAnalyzer;
    private final SequenceAnalyzer    sequenceAnalyzer;
    private final RemediationService  remediationService;
    private final ReportGenerator     reportGenerator;
    private final List<SecurityRule>  rules;
    private final List<SuppressionRule> suppressions;

    public SASTEngine() throws IOException {
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());

        ParserConfiguration config = new ParserConfiguration()
                .setSymbolResolver(new JavaSymbolSolver(typeSolver));
        this.parser = new JavaParser(config);

        this.taintEngine        = new TaintAnalysisEngine();
        this.patternAnalyzer    = new PatternAnalyzer();
        this.sequenceAnalyzer   = new SequenceAnalyzer();
        this.remediationService = new RemediationService();
        this.reportGenerator    = new ReportGenerator(remediationService);

        this.rules       = RuleLoader.loadFromClasspath("security-rules.json");
        this.suppressions = SuppressionLoader.load("sast-suppressions.json");
        log.info("[SAST] 보안 규칙 로드 완료: {}개, 억제 규칙: {}개",
                rules.size(), suppressions.size());
    }

    // ── Public API ────────────────────────────────────────────────────────

    public void analyzeDirectory(String sourceDirectory, String outputPath) throws IOException {
        List<Path> javaFiles = collectJavaFiles(sourceDirectory);
        log.info("[SAST] 분석 대상 파일 수: {}개", javaFiles.size());

        List<Finding> allFindings = new ArrayList<>();
        for (Path file : javaFiles) {
            log.info("[SAST] 분석 중: {}", file);
            try {
                List<Finding> findings = analyzeFile(file.toFile());
                allFindings.addAll(findings);
            } catch (IOException e) {
                log.warn("[SAST] 파일 분석 건너뜀: {} — {}", file, e.getMessage());
            }
        }

        // 위험도 오름차순 (CRITICAL=0이 먼저)
        allFindings.sort(Comparator.comparingInt(f -> f.getSeverity().ordinal()));

        reportGenerator.printConsoleSummary(allFindings);

        String mdReport = reportGenerator.generateMarkdown(allFindings, sourceDirectory);
        Files.write(Paths.get(outputPath), mdReport.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        log.info("[SAST] Markdown 리포트 저장: {}", outputPath);

        String jsonReport = reportGenerator.generateJson(allFindings, sourceDirectory);
        String jsonPath   = outputPath.replace(".md", ".json");
        Files.write(Paths.get(jsonPath), jsonReport.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        log.info("[SAST] JSON 리포트 저장: {}", jsonPath);

        // PDF 리포트 생성
        try {
            PdfReportGenerator pdfGen = new PdfReportGenerator();
            byte[] pdfBytes = pdfGen.generateFromFindings(allFindings, remediationService, sourceDirectory);
            String pdfPath = outputPath.replace(".md", ".pdf");
            Files.write(Paths.get(pdfPath), pdfBytes);
            log.info("[SAST] PDF 리포트 저장: {}", pdfPath);
        } catch (Exception e) {
            log.warn("[SAST] PDF 생성 실패 (MD/JSON은 정상 저장됨): {}", e.getMessage());
        }
    }

    public List<Finding> analyzeFile(File javaFile) throws IOException {
        String filePath = javaFile.getAbsolutePath();

        // Group A: taintAnalysis: true → TaintAnalysisEngine (AST 기반)
        List<SecurityRule> taintRules = rules.stream()
                .filter(SecurityRule::isTaintAnalysis)
                .collect(Collectors.toList());

        // Group B: sequenceAnalysis: true → SequenceAnalyzer (TOCTOU 시퀀스 탐지, IV-3.1)
        List<SecurityRule> sequenceRules = rules.stream()
                .filter(SecurityRule::isSequenceAnalysis)
                .collect(Collectors.toList());

        // Group C: 나머지 → PatternAnalyzer (정규식 기반)
        List<SecurityRule> patternRules = rules.stream()
                .filter(r -> !r.isTaintAnalysis() && !r.isSequenceAnalysis())
                .collect(Collectors.toList());

        List<Finding> combined = new ArrayList<>();
        CompilationUnit cu = null;

        // Track A — AST 파싱 필요 (Taint 분석 + Sequence 분석 공용)
        ParseResult<CompilationUnit> result = parser.parse(javaFile);
        if (!result.isSuccessful() || !result.getResult().isPresent()) {
            log.warn("[SAST] 파싱 실패: {}", filePath);
            result.getProblems().forEach(p -> log.warn("  {}", p.getMessage()));
        } else {
            cu = result.getResult().get();
            combined.addAll(taintEngine.analyze(cu, filePath, taintRules));

            // Track B — TOCTOU 시퀀스 분석 (IV-3.1, CWE-367)
            for (SecurityRule seqRule : sequenceRules) {
                combined.addAll(sequenceAnalyzer.analyze(cu, filePath, seqRule));
            }
        }

        // Track C — 소스 텍스트 라인 스캔 (정규식 기반, 주석 라인 자동 제외)
        combined.addAll(patternAnalyzer.analyze(filePath, patternRules));

        // ── 오탐 필터링 (Post-Processing) ─────────────────────────────────

        // [1] @SuppressWarnings("sast-ignore") 어노테이션 메서드 내 탐지 제외
        if (cu != null) {
            combined = filterBySuppressAnnotation(combined, cu);
        }

        // [2] src/test/ 경로 위험도 하향 (완전 제외 아닌 LOW 표시)
        combined = FalsePositiveFilter.lowerTestPathSeverity(combined);

        // [3] sast-suppressions.json 사용자 정의 억제 적용
        combined = FalsePositiveFilter.apply(combined, suppressions);

        log.debug("[SAST] {} — Taint {}건 + Sequence {}건 + Pattern {}건 (필터 후 {}건)",
                javaFile.getName(),
                combined.stream().filter(f -> taintRules.stream()
                        .anyMatch(r -> r.getRuleId().equals(f.getRuleId()))).count(),
                combined.stream().filter(f -> sequenceRules.stream()
                        .anyMatch(r -> r.getRuleId().equals(f.getRuleId()))).count(),
                combined.stream().filter(f -> patternRules.stream()
                        .anyMatch(r -> r.getRuleId().equals(f.getRuleId()))).count(),
                combined.size());

        return combined;
    }

    // ── 오탐 필터: @SuppressWarnings("sast-ignore") ───────────────────────

    /**
     * @SuppressWarnings("sast-ignore") 어노테이션이 붙은 메서드 내부의 탐지 결과를 제거
     * 소스코드 레벨 오탐 표시를 SAST 분석 결과에 반영 (IV-6.2)
     */
    private List<Finding> filterBySuppressAnnotation(List<Finding> findings, CompilationUnit cu) {
        List<int[]> suppressedRanges = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            boolean suppressed = method.getAnnotations().stream()
                    .anyMatch(a -> a.getNameAsString().equals("SuppressWarnings")
                                  && a.toString().contains("sast-ignore"));
            if (suppressed) {
                int start = method.getBegin().map(p -> p.line).orElse(-1);
                int end   = method.getEnd().map(p -> p.line).orElse(-1);
                if (start > 0 && end > 0) {
                    suppressedRanges.add(new int[]{start, end});
                    log.debug("[SAST] @SuppressWarnings(sast-ignore) 억제 범위: L{}-L{}", start, end);
                }
            }
        });

        if (suppressedRanges.isEmpty()) return findings;

        List<Finding> filtered = findings.stream()
                .filter(f -> suppressedRanges.stream()
                        .noneMatch(r -> f.getLineNumber() >= r[0] && f.getLineNumber() <= r[1]))
                .collect(Collectors.toList());

        int suppressed = findings.size() - filtered.size();
        if (suppressed > 0) {
            log.info("[SAST] @SuppressWarnings(sast-ignore) {}건 억제됨", suppressed);
        }
        return filtered;
    }

    // ── Utility ───────────────────────────────────────────────────────────

    private List<Path> collectJavaFiles(String dir) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(Paths.get(dir), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (file.toString().endsWith(".java")) {
                    files.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return files;
    }

    // ── Entry Point ───────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java -jar sast.jar <소스_디렉터리> <리포트_출력_경로>");
            System.out.println("Example: java -jar sast.jar ./src/main/java ./report.md");
            System.exit(1);
        }
        SASTEngine engine = new SASTEngine();
        engine.analyzeDirectory(args[0], args[1]);
    }
}
