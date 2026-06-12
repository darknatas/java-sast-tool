package com.sast.web;

import com.sast.SASTEngine;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.web.model.AnalysisResultView;
import com.sast.web.model.FindingView;
import jakarta.annotation.PostConstruct;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 *   - 디스크 폭탄 방어: 스트리밍 ZIP 포함 기록량 기준 즉시 중단 (copyWithLimit)
 *   - 7z 심볼릭 링크 차단: 엔트리 단위로 디스크에 쓰기 전 거부
 *   - 압축 해제는 순수 자바(ZIP: java.util.zip, 7z: Commons Compress)로 OS 비의존
 *   - 분석 완료 후 임시 디렉터리 자동 삭제 (finally 블록)
 */
@Service
public class SastAnalysisService {

    private static final Logger log         = LoggerFactory.getLogger(SastAnalysisService.class);
    private static final int    MAX_ENTRIES       = 10_000;              // ZIP 폭탄 방지 (IV-1.6)
    private static final long   MAX_EXTRACT_BYTES = 300L * 1024 * 1024; // 디스크 폭탄 방지: 300MB

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
                                "압축 해제 용량 합계가 300MB 한도를 초과합니다. 분석을 중단합니다.");
                    }

                    Files.createDirectories(target.getParent());
                    // 스트리밍 ZIP(getSize() == -1)은 선제 체크가 불가능하므로
                    // 실제 기록량 기준으로 한도 초과 시 쓰기 도중 즉시 중단 (IV-1.6)
                    long written = copyWithLimit(zis, target, MAX_EXTRACT_BYTES - totalBytes[0]);
                    totalBytes[0] += written;

                    if (entry.getName().endsWith(".java")) {
                        fileCount[0]++;
                    }
                }
                zis.closeEntry();
            }
        }
    }

    /**
     * 입력 스트림을 target 파일로 복사하되, remainingBudget 초과 시 즉시 중단한다.
     * entry.getSize()가 -1인 스트리밍 ZIP은 선제 크기 체크를 우회하므로
     * 복사 도중 실제 기록량을 기준으로 디스크 폭탄을 차단한다. (IV-1.6)
     */
    private long copyWithLimit(InputStream in, Path target, long remainingBudget) throws IOException {
        long written = 0;
        byte[] buffer = new byte[8192];
        try (OutputStream out = Files.newOutputStream(target)) {
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (written + n > remainingBudget) {
                    throw new SecurityException(
                            "압축 해제 용량 합계가 300MB 한도를 초과합니다. 분석을 중단합니다.");
                }
                out.write(buffer, 0, n);
                written += n;
            }
        }
        return written;
    }

    // ── 7z 압축 해제 (Apache Commons Compress — 순수 자바, OS 비의존) ────

    /**
     * 7z 아카이브를 순수 자바(Commons Compress SevenZFile)로 해제한다.
     * 시스템 7za 바이너리에 의존하지 않으며, 엔트리 단위로 ZIP 경로와 동일한
     * 보안 검사(심링크 거부 → 경로 탈출 방어 → 용량 한도)를 적용한다.
     */
    private void extract7z(Path sevenZPath, Path destDir,
                           int[] fileCount, long[] totalBytes) throws IOException {
        Path normalizedDest = destDir.normalize();
        int entryCount = 0;

        try (SevenZFile sevenZFile = SevenZFile.builder().setFile(sevenZPath.toFile()).get()) {
            SevenZArchiveEntry entry;
            while ((entry = sevenZFile.getNextEntry()) != null) {
                if (++entryCount > MAX_ENTRIES) {
                    throw new SecurityException("7z 항목 수가 허용 한도(" + MAX_ENTRIES + ")를 초과합니다.");
                }

                // 심볼릭 링크는 디스크에 쓰기 전에 거부한다. 링크가 생성되면 분석 단계가
                // 링크를 따라 서버 파일을 읽거나 경로를 탈출할 수 있다. (IV-1.3)
                if (isSymlinkEntry(entry)) {
                    log.warn("[SECURITY] 7z 심볼릭 링크 항목 차단: {}", entry.getName());
                    throw new SecurityException(
                            "7z 아카이브에 심볼릭 링크 항목이 포함되어 있습니다: " + entry.getName());
                }

                // 7z Slip 방어: normalize() 후 destDir 범위 내인지 확인 (IV-1.3)
                Path target = destDir.resolve(entry.getName()).normalize();
                if (!target.startsWith(normalizedDest)) {
                    log.warn("[SECURITY] 7z 경로 탈출 시도 탐지: {}", entry.getName());
                    throw new SecurityException("7z 경로 탈출이 탐지되었습니다: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                    continue;
                }

                Files.createDirectories(target.getParent());
                // 디스크 폭탄 방어: 실제 기록량 기준으로 한도 초과 시 즉시 중단 (IV-1.6)
                // 솔리드 아카이브에서는 getInputStream(entry)(랜덤 접근)이 엔트리마다 블록을
                // 재해제해 O(n²)로 느려지므로, 현재 엔트리를 순차 read하는 어댑터를 사용한다.
                long written = copyWithLimit(currentEntryStream(sevenZFile),
                        target, MAX_EXTRACT_BYTES - totalBytes[0]);
                totalBytes[0] += written;

                if (entry.getName().endsWith(".java")) {
                    fileCount[0]++;
                }
            }
        }
    }

    /**
     * SevenZFile의 현재 엔트리를 순차로 읽는 InputStream 어댑터.
     * close()는 의도적으로 무시한다 — 스트림을 닫아도 SevenZFile 본체는 유지되어야
     * 다음 getNextEntry() 호출이 가능하다 (close는 try-with-resources가 본체에 적용).
     */
    private InputStream currentEntryStream(SevenZFile sevenZFile) {
        return new InputStream() {
            @Override public int read() throws IOException { return sevenZFile.read(); }
            @Override public int read(byte[] b, int off, int len) throws IOException {
                return sevenZFile.read(b, off, len);
            }
        };
    }

    /**
     * 7z 엔트리가 유닉스 심볼릭 링크인지 판별한다.
     * 7z는 유닉스 퍼미션을 windowsAttributes 상위 16비트에 저장하며,
     * UNIX 확장 비트(0x8000)가 켜져 있고 모드의 파일 유형이 S_IFLNK(0xA000)이면 링크다.
     */
    private boolean isSymlinkEntry(SevenZArchiveEntry entry) {
        if (!entry.getHasWindowsAttributes()) return false;
        int attr = entry.getWindowsAttributes();
        final int FILE_ATTRIBUTE_UNIX_EXTENSION = 0x8000;
        if ((attr & FILE_ATTRIBUTE_UNIX_EXTENSION) == 0) return false;
        final int S_IFMT = 0xF000, S_IFLNK = 0xA000;
        return ((attr >>> 16) & S_IFMT) == S_IFLNK;
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
