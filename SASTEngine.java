package com.sast;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.engine.taint.TaintAnalysisEngine;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.report.ReportGenerator;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

/**
 * Java SAST (Static Application Security Testing) Engine
 *
 * 진입점 클래스 — 전체 분석 파이프라인을 조율합니다.
 *
 * 파이프라인:
 *   [1] Java 소스 파일 수집
 *   [2] JavaParser로 AST 파싱
 *   [3] 보안 규칙 로드 (security-rules.json)
 *   [4] TaintAnalysisEngine으로 오염 흐름 분석
 *   [5] PatternAnalyzer로 패턴 기반 추가 탐지
 *   [6] RemediationService로 수정 코드 생성
 *   [7] ReportGenerator로 리포트 출력
 */
public class SASTEngine {

    private final JavaParser          parser;
    private final TaintAnalysisEngine taintEngine;
    private final RemediationService  remediationService;
    private final ReportGenerator     reportGenerator;
    private final List<SecurityRule>  rules;

    public SASTEngine() throws IOException {
        // JavaParser 설정: Symbol Solver로 타입 해석 활성화
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());

        ParserConfiguration config = new ParserConfiguration()
                .setSymbolResolver(new JavaSymbolSolver(typeSolver));
        this.parser = new JavaParser(config);

        // 컴포넌트 초기화
        this.taintEngine       = new TaintAnalysisEngine();
        this.remediationService = new RemediationService();
        this.reportGenerator   = new ReportGenerator(remediationService);

        // 규칙 로드
        this.rules = RuleLoader.loadFromClasspath("security-rules.json");
        System.out.println("[SAST] 보안 규칙 로드 완료: " + rules.size() + "개");
    }

    // ────────────────────────────────────────────────────────────────────
    //  Public API
    // ────────────────────────────────────────────────────────────────────

    /**
     * 지정된 디렉터리 내 모든 Java 파일을 분석합니다.
     *
     * @param sourceDirectory 분석 대상 Java 소스 루트 경로
     * @param outputPath      리포트 출력 파일 경로 (Markdown)
     */
    public void analyzeDirectory(String sourceDirectory, String outputPath) throws IOException {
        List<Path> javaFiles = collectJavaFiles(sourceDirectory);
        System.out.println("[SAST] 분석 대상 파일 수: " + javaFiles.size() + "개");

        List<Finding> allFindings = new ArrayList<>();

        for (Path file : javaFiles) {
            System.out.println("[SAST] 분석 중: " + file);
            List<Finding> findings = analyzeFile(file.toFile());
            allFindings.addAll(findings);
        }

        // 위험도 내림차순 정렬
        allFindings.sort(Comparator.comparing(f -> f.getSeverity().ordinal()));

        // 리포트 출력
        reportGenerator.printConsoleSummary(allFindings);

        String mdReport = reportGenerator.generateMarkdown(allFindings, sourceDirectory);
        Files.writeString(Path.of(outputPath), mdReport);
        System.out.println("[SAST] Markdown 리포트 저장: " + outputPath);

        String jsonReport = reportGenerator.generateJson(allFindings, sourceDirectory);
        String jsonPath   = outputPath.replace(".md", ".json");
        Files.writeString(Path.of(jsonPath), jsonReport);
        System.out.println("[SAST] JSON 리포트 저장: " + jsonPath);
    }

    /**
     * 단일 Java 파일을 분석합니다.
     */
    public List<Finding> analyzeFile(File javaFile) throws IOException {
        ParseResult<CompilationUnit> result = parser.parse(javaFile);

        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            System.err.println("[SAST] 파싱 실패: " + javaFile.getPath());
            result.getProblems().forEach(p -> System.err.println("  " + p.getMessage()));
            return List.of();
        }

        CompilationUnit cu = result.getResult().get();
        String filePath    = javaFile.getAbsolutePath();

        // Taint 분석 (규칙에 taintAnalysis: true인 항목만)
        List<SecurityRule> taintRules = rules.stream()
                .filter(SecurityRule::isTaintAnalysis)
                .toList();

        return taintEngine.analyze(cu, filePath, taintRules);
    }

    // ────────────────────────────────────────────────────────────────────
    //  Utility
    // ────────────────────────────────────────────────────────────────────

    private List<Path> collectJavaFiles(String dir) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(Path.of(dir), new SimpleFileVisitor<>() {
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

    // ── Entry Point ──────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java -jar sast.jar <소스_디렉터리> <리포트_출력_경로>");
            System.out.println("Example: java -jar sast.jar ./src/main/java ./report.md");
            System.exit(1);
        }
        String sourceDir  = args[0];
        String outputPath = args[1];

        SASTEngine engine = new SASTEngine();
        engine.analyzeDirectory(sourceDir, outputPath);
    }
}
