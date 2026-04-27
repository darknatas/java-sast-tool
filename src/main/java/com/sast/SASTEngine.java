package com.sast;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.sast.engine.pattern.PatternAnalyzer;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.engine.sequence.SequenceAnalyzer;
import com.sast.engine.taint.TaintAnalysisEngine;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
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
 *   [5] RemediationService 수정 코드 생성
 *   [6] ReportGenerator 리포트 출력 (MD + JSON)
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

        this.rules = RuleLoader.loadFromClasspath("security-rules.json");
        log.info("[SAST] 보안 규칙 로드 완료: {}개", rules.size());
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

        // Track A — AST 파싱 필요 (Taint 분석 + Sequence 분석 공용)
        ParseResult<CompilationUnit> result = parser.parse(javaFile);
        if (!result.isSuccessful() || !result.getResult().isPresent()) {
            log.warn("[SAST] 파싱 실패: {}", filePath);
            result.getProblems().forEach(p -> log.warn("  {}", p.getMessage()));
        } else {
            CompilationUnit cu = result.getResult().get();
            combined.addAll(taintEngine.analyze(cu, filePath, taintRules));

            // Track B — TOCTOU 시퀀스 분석 (IV-3.1, CWE-367)
            for (SecurityRule seqRule : sequenceRules) {
                combined.addAll(sequenceAnalyzer.analyze(cu, filePath, seqRule));
            }
        }

        // Track C — 소스 텍스트 라인 스캔 (정규식 기반)
        combined.addAll(patternAnalyzer.analyze(filePath, patternRules));

        log.debug("[SAST] {} — Taint {}건 + Pattern {}건", javaFile.getName(),
                combined.stream().filter(f -> taintRules.stream()
                        .anyMatch(r -> r.getRuleId().equals(f.getRuleId()))).count(),
                combined.stream().filter(f -> patternRules.stream()
                        .anyMatch(r -> r.getRuleId().equals(f.getRuleId()))).count());

        return combined;
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
