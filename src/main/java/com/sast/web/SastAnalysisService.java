package com.sast.web;

import com.sast.SASTEngine;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.web.model.AnalysisResultView;
import com.sast.web.model.FindingView;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * SAST 분석 서비스 — ZIP 업로드 → 압축 해제 → 분석 → 임시 파일 정리
 *
 * 보안 처리:
 *   - Zip Slip 방어: 추출 경로가 tempDir 외부를 벗어나면 즉시 거부
 *   - 파일 크기·개수 제한: application.properties + MAX_ENTRIES 상수
 *   - 분석 완료 후 임시 디렉터리 자동 삭제 (finally 블록)
 */
@Service
public class SastAnalysisService {

    private static final Logger log         = LoggerFactory.getLogger(SastAnalysisService.class);
    private static final int    MAX_ENTRIES       = 10_000;              // ZIP 폭탄 방지 (IV-1.6)
    private static final long   MAX_EXTRACT_BYTES = 100L * 1024 * 1024; // 디스크 폭탄 방지: 100MB

    private SASTEngine         engine;
    private RemediationService remediationService;

    @PostConstruct
    public void init() throws IOException {
        this.engine            = new SASTEngine();
        this.remediationService = new RemediationService();
        log.info("[SAST-Web] 분석 엔진 초기화 완료");
    }

    // ── Public API ────────────────────────────────────────────────────────

    public AnalysisResultView analyze(MultipartFile uploadedFile) throws IOException {
        String originalName = uploadedFile.getOriginalFilename() != null
                ? uploadedFile.getOriginalFilename() : "unknown";
        String lowerName = originalName.toLowerCase();

        Path tempDir = Files.createTempDirectory("sast-upload-");
        log.info("[SAST-Web] 임시 디렉터리 생성: {}", tempDir);

        try {
            int[]  fileCount  = {0};
            long[] totalBytes = {0L};
            if (lowerName.endsWith(".7z")) {
                Path tempFile = Files.createTempFile("sast-7z-", ".7z");
                try {
                    uploadedFile.transferTo(tempFile);
                    extract7z(tempFile, tempDir, fileCount, totalBytes);
                } finally {
                    Files.deleteIfExists(tempFile);
                }
                log.info("[SAST-Web] 7z 압축 해제 완료: {} 파일, {}KB", fileCount[0], totalBytes[0] / 1024);
            } else {
                extractZip(uploadedFile.getInputStream(), tempDir, fileCount, totalBytes);
                log.info("[SAST-Web] ZIP 압축 해제 완료: {} 파일, {}KB", fileCount[0], totalBytes[0] / 1024);
            }

            List<FindingView> findings = runAnalysis(tempDir);
            log.info("[SAST-Web] 분석 완료: {}건 탐지", findings.size());

            return new AnalysisResultView(originalName, fileCount[0], findings);


        } finally {
            deleteDirectory(tempDir);
            log.info("[SAST-Web] 임시 디렉터리 삭제 완료: {}", tempDir);
        }
    }

    // ── ZIP 압축 해제 (Zip Slip 방어) ────────────────────────────────────

    private void extractZip(InputStream inputStream, Path destDir,
                            int[] fileCount, long[] totalBytes) throws IOException {
        // EUC-KR fallback: UTF-8 flag가 없는 구형 한글 ZIP 파일명 깨짐 방지
        try (ZipInputStream zis = new ZipInputStream(inputStream, Charset.forName("EUC-KR"))) {
            ZipEntry entry;
            int entryCount = 0;

            while ((entry = zis.getNextEntry()) != null) {
                if (++entryCount > MAX_ENTRIES) {
                    throw new SecurityException("ZIP 항목 수가 허용 한도(" + MAX_ENTRIES + ")를 초과합니다.");
                }

                // Zip Slip 방어: normalize() 후 tempDir 범위 내인지 확인 (IV-1.3)
                Path target = destDir.resolve(entry.getName()).normalize();
                if (!target.startsWith(destDir)) {
                    log.warn("[SECURITY] Zip Slip 시도 탐지: {}", entry.getName());
                    throw new SecurityException("ZIP Slip 공격이 탐지되었습니다: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    // 디스크 폭탄 방어: 선제 크기 체크 (entry.getSize()가 유효한 경우)
                    long declared = entry.getSize();
                    if (declared > 0 && totalBytes[0] + declared > MAX_EXTRACT_BYTES) {
                        throw new SecurityException(
                                "압축 해제 용량 합계가 100MB 한도를 초과합니다. 분석을 중단합니다.");
                    }

                    Files.createDirectories(target.getParent());
                    long written = Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
                    totalBytes[0] += written;

                    // 사후 크기 체크 (선제 체크가 불가능했던 경우 커버)
                    if (totalBytes[0] > MAX_EXTRACT_BYTES) {
                        throw new SecurityException(
                                "압축 해제 용량 합계가 100MB 한도를 초과합니다. 분석을 중단합니다.");
                    }

                    if (entry.getName().endsWith(".java")) {
                        fileCount[0]++;
                    }
                }
                zis.closeEntry();
            }
        }
    }

    // ── 7z 압축 해제 (Zip Slip 방어) ─────────────────────────────────────

    private void extract7z(Path sevenZPath, Path destDir,
                           int[] fileCount, long[] totalBytes) throws IOException {
        try (SevenZFile sevenZFile = SevenZFile.builder().setPath(sevenZPath).get()) {
            SevenZArchiveEntry entry;
            int entryCount = 0;

            while ((entry = sevenZFile.getNextEntry()) != null) {
                if (++entryCount > MAX_ENTRIES) {
                    throw new SecurityException("7z 항목 수가 허용 한도(" + MAX_ENTRIES + ")를 초과합니다.");
                }

                Path target = destDir.resolve(entry.getName()).normalize();
                if (!target.startsWith(destDir)) {
                    log.warn("[SECURITY] 7z Path Traversal 시도 탐지: {}", entry.getName());
                    throw new SecurityException("7z 경로 탈출 공격이 탐지되었습니다: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    // 디스크 폭탄 방어: 7z 엔트리는 항상 압축 해제 크기 제공
                    long declared = entry.getSize();
                    if (declared > 0 && totalBytes[0] + declared > MAX_EXTRACT_BYTES) {
                        throw new SecurityException(
                                "압축 해제 용량 합계가 100MB 한도를 초과합니다. 분석을 중단합니다.");
                    }

                    Files.createDirectories(target.getParent());
                    try (InputStream is = sevenZFile.getInputStream(entry)) {
                        long written = Files.copy(is, target, StandardCopyOption.REPLACE_EXISTING);
                        totalBytes[0] += written;
                    }

                    if (totalBytes[0] > MAX_EXTRACT_BYTES) {
                        throw new SecurityException(
                                "압축 해제 용량 합계가 100MB 한도를 초과합니다. 분석을 중단합니다.");
                    }

                    if (entry.getName().endsWith(".java")) {
                        fileCount[0]++;
                    }
                }
            }
        }
    }

    // ── 디렉터리 내 Java 파일 분석 ───────────────────────────────────────

    private List<FindingView> runAnalysis(Path dir) throws IOException {
        List<Path> javaFiles = collectJavaFiles(dir);
        List<FindingView> results = new ArrayList<>();

        for (Path file : javaFiles) {
            try {
                List<Finding> findings = engine.analyzeFile(file.toFile());
                for (Finding finding : findings) {
                    RemediationService.RemediationResult remediation = remediationService.suggest(finding);
                    results.add(new FindingView(finding, remediation));
                }
            } catch (IOException e) {
                log.warn("[SAST-Web] 파일 분석 건너뜀: {} — {}", file, e.getMessage());
            }
        }

        // 위험도 내림차순 (CRITICAL → HIGH → MEDIUM → LOW)
        results.sort(Comparator.comparingInt(v -> v.getFinding().getSeverity().ordinal()));
        return results;
    }

    // ── 유틸리티 ─────────────────────────────────────────────────────────

    private List<Path> collectJavaFiles(Path dir) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
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

    private void deleteDirectory(Path dir) {
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.delete(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.warn("[SAST-Web] 임시 디렉터리 삭제 실패: {} — {}", dir, e.getMessage());
        }
    }
}
