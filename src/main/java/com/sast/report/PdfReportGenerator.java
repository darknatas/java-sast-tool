package com.sast.report;

import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.web.model.AnalysisResultView;
import com.sast.web.model.FindingView;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.Color;
import java.io.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * OpenPDF 기반 PDF 리포트 생성기 — 한국어(UTF-8) 완전 지원
 *
 * 폰트: NotoSansCJKkr OTF (CFF 기반 한국어 폰트)
 *   BaseFont.IDENTITY_H 인코딩으로 모든 한글/CJK 문자 렌더링
 *
 * 구성:
 *   1페이지: 표지 + 위험도별 통계 + 바 차트
 *   2페이지: 핵심 취약점 TOP 5
 *   3페이지~: 상세 취약점 목록 (파일·라인·취약코드·권고수정)
 *
 * 레이아웃 전략:
 *   - PdfPTable / PdfPCell: 헤더 배너, 바 차트, 코드 블록
 *   - Paragraph / Chunk: 본문 텍스트 흐름
 *   - OpenPDF flow engine이 페이지 나눔을 자동 처리
 */
@Component
public class PdfReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(PdfReportGenerator.class);

    // 한국어 OTF (CFF 기반) — OpenPDF BaseFont.IDENTITY_H로 지원
    private static final String FONT_KOR_REG  = "/usr/share/fonts/google-noto-cjk/NotoSansCJKkr-Regular.otf";
    private static final String FONT_KOR_BOLD = "/usr/share/fonts/google-noto-cjk/NotoSansCJKkr-Bold.otf";
    // 코드 블록용 한글 지원 고정폭 폰트 (Noto Sans Mono CJK KR — index 6 in TTC)
    private static final String FONT_MONO_KOR = "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc,6";
    // 한글 미지원 Latin 폴백
    private static final String FONT_MONO_LAT = "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf";

    // 규칙 ID → SecurityRule (codeExamples 조회용)
    private final Map<String, SecurityRule> ruleMap = new HashMap<>();

    @PostConstruct
    private void initRuleMap() {
        try {
            List<SecurityRule> rules = RuleLoader.loadFromClasspath("security-rules.json");
            for (SecurityRule r : rules) {
                ruleMap.put(r.getRuleId(), r);
            }
            log.info("[PDF] 보안 규칙 {}개 로드 완료 (codeExamples 렌더링 준비)", ruleMap.size());
        } catch (Exception e) {
            log.warn("[PDF] 규칙 로드 실패 — codeExamples 섹션이 생략됩니다: {}", e.getMessage());
        }
    }

    // 색상 팔레트
    private static final Color NAVY      = new Color(30,  58, 138);
    private static final Color SLATE     = new Color(30,  41,  59);
    private static final Color GRAY_DARK = new Color(100, 116, 139);
    private static final Color GRAY_BG   = new Color(248, 250, 252);
    private static final Color GRAY_LINE = new Color(226, 232, 240);
    private static final Color LAVENDER  = new Color(199, 210, 254);

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * AnalysisResultView → PDF 바이트 배열
     */
    public byte[] generate(AnalysisResultView result) throws IOException {
        if (ruleMap.isEmpty()) initRuleMap();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 40, 40, 40, 50);
        PdfWriter writer = PdfWriter.getInstance(document, out);
        document.open();

        FontSet fonts = loadFonts();

        writeCoverPage(document, writer, fonts, result);
        document.newPage();
        writeTop5Page(document, writer, fonts, result);
        document.newPage();
        writeDetailsPages(document, fonts, result);

        document.close();
        log.info("[PDF] 생성 완료 — {}건, {}KB", result.getTotalFindings(), out.size() / 1024);
        return out.toByteArray();
    }

    /**
     * CLI 모드용: List<Finding> → PDF
     */
    public byte[] generateFromFindings(List<Finding> findings,
                                       RemediationService remService,
                                       String sourceName) throws IOException {
        List<FindingView> views = findings.stream()
                .map(f -> new FindingView(f, remService.suggest(f)))
                .collect(Collectors.toList());
        long fileCount = findings.stream().map(Finding::getFilePath).distinct().count();
        AnalysisResultView view = new AnalysisResultView(sourceName, (int) fileCount, views);
        return generate(view);
    }

    // ── 폰트 로드 ─────────────────────────────────────────────────────────

    private record FontSet(BaseFont reg, BaseFont bold, BaseFont mono) {}

    private FontSet loadFonts() {
        BaseFont reg  = null;
        BaseFont bold = null;

        // 한국어 OTF CFF: OpenPDF BaseFont.IDENTITY_H 인코딩으로 로드
        for (String path : new String[]{FONT_KOR_REG}) {
            if (!new File(path).exists()) continue;
            try {
                reg = BaseFont.createFont(path, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                log.info("[PDF] 한국어 폰트 로드: {}", path);
                break;
            } catch (Exception e) {
                log.warn("[PDF] 폰트 로드 실패 {}: {}", path, e.getMessage());
            }
        }
        if (new File(FONT_KOR_BOLD).exists() && reg != null) {
            try {
                bold = BaseFont.createFont(FONT_KOR_BOLD, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            } catch (Exception e) {
                bold = reg;
            }
        }
        if (reg == null) {
            log.warn("[PDF] 한국어 폰트 없음 — Helvetica 폴백 (한글이 렌더링되지 않을 수 있음)");
            try {
                reg  = BaseFont.createFont(BaseFont.HELVETICA,      BaseFont.WINANSI, false);
                bold = BaseFont.createFont(BaseFont.HELVETICA_BOLD, BaseFont.WINANSI, false);
            } catch (Exception ignored) {}
        }
        if (bold == null) bold = reg;

        // 1순위: Noto Sans Mono CJK KR (한글 지원 고정폭, TTC index 6)
        BaseFont mono = null;
        try {
            mono = BaseFont.createFont(FONT_MONO_KOR, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            log.info("[PDF] 한글 모노 폰트 로드: Noto Sans Mono CJK KR");
        } catch (Exception e) {
            log.warn("[PDF] 한글 모노 폰트 로드 실패, Latin 폴백 시도: {}", e.getMessage());
        }
        // 2순위: DejaVu Sans Mono (Latin 전용)
        if (mono == null && new File(FONT_MONO_LAT).exists()) {
            try {
                mono = BaseFont.createFont(FONT_MONO_LAT, BaseFont.WINANSI, BaseFont.EMBEDDED);
            } catch (Exception e) {
                log.warn("[PDF] Latin 모노 폰트 로드 실패: {}", e.getMessage());
            }
        }
        // 3순위: 내장 Courier
        if (mono == null) {
            try {
                mono = BaseFont.createFont(BaseFont.COURIER, BaseFont.WINANSI, false);
            } catch (Exception ignored) {}
        }
        return new FontSet(reg, bold, mono);
    }

    // ── 1페이지: 표지 + 통계 ─────────────────────────────────────────────

    private void writeCoverPage(Document doc, PdfWriter writer,
                                FontSet f, AnalysisResultView result) throws DocumentException {
        // 헤더 배너
        doc.add(headerBanner(f, "Java SAST 보안 분석 리포트",
                "소프트웨어 보안약점 진단가이드(2021) 기반  |  분석 일자: "
                + LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy년 MM월 dd일")),
                20, 10));

        // 분석 파일 정보
        doc.add(space(6));
        PdfPTable meta = tbl(2, new float[]{3, 7});
        addCell(meta, cell(phrase("분석 대상 파일", f.bold(), 10, NAVY), GRAY_BG, 8, 1));
        addCell(meta, cell(phrase(result.getUploadedFileName(), f.reg(), 10, SLATE), GRAY_BG, 8, 1));
        addCell(meta, cell(phrase("총 탐지 취약점", f.bold(), 10, NAVY), GRAY_BG, 8, 1));
        addCell(meta, cell(phrase(result.getTotalFindings() + "건  (Java " + result.getTotalFiles() + "개 파일 분석)",
                f.bold(), 12, NAVY), GRAY_BG, 8, 1));
        doc.add(meta);

        // 위험도 통계 섹션
        doc.add(space(10));
        doc.add(sectionTitle(f, "위험도별 통계"));

        int total = Math.max(result.getTotalFindings(), 1);
        doc.add(buildSeverityTable(f,
                result.getCriticalCount(), result.getHighCount(),
                result.getMediumCount(),   result.getLowCount(), total));

        // 바 차트 섹션
        doc.add(space(8));
        doc.add(sectionTitle(f, "위험도 분포"));
        long[] cnts = {result.getCriticalCount(), result.getHighCount(),
                       result.getMediumCount(), result.getLowCount()};
        String[] labels = {"CRITICAL", "HIGH   ", "MEDIUM ", "LOW    "};
        Color[] colors  = {sevColor(Finding.Severity.CRITICAL), sevColor(Finding.Severity.HIGH),
                           sevColor(Finding.Severity.MEDIUM),   sevColor(Finding.Severity.LOW)};
        long maxCnt = Arrays.stream(cnts).max().orElse(1);

        PdfPTable chartTbl = tbl(3, new float[]{2, 6, 2});
        for (int i = 0; i < 4; i++) {
            addCell(chartTbl, noBorderCell(phrase(labels[i], f.mono(), 9, GRAY_DARK), 6, 1));
            addCell(chartTbl, noBorderCell(barChart(cnts[i], maxCnt, colors[i]), 2, 1));
            addCell(chartTbl, noBorderCell(phrase(cnts[i] + "건", f.bold(), 9, colors[i]), 6, 1));
        }
        doc.add(chartTbl);

        // 푸터
        doc.add(space(14));
        PdfPTable footer = tbl(1, new float[]{1});
        PdfPCell fc = noBorderCell(phrase(
                "이 리포트는 Java SAST Engine에 의해 자동 생성되었습니다. " +
                "(행정안전부 소프트웨어 보안약점 진단가이드 2021 기준)", f.reg(), 8, GRAY_DARK), 4, 1);
        fc.setHorizontalAlignment(Element.ALIGN_CENTER);
        addCell(footer, fc);
        doc.add(footer);
    }

    private PdfPTable buildSeverityTable(FontSet f,
                                         long crit, long high, long med, long low,
                                         int total) {
        PdfPTable t = tbl(4, new float[]{1, 1, 1, 1});
        t.setSpacingBefore(4);
        for (Object[] row : new Object[][]{
                {"CRITICAL\n치명", crit,  sevColor(Finding.Severity.CRITICAL)},
                {"HIGH\n높음",     high,  sevColor(Finding.Severity.HIGH)},
                {"MEDIUM\n중간",   med,   sevColor(Finding.Severity.MEDIUM)},
                {"LOW\n낮음",      low,   sevColor(Finding.Severity.LOW)}
        }) {
            String label = (String) row[0];
            long   cnt   = (long)   row[1];
            Color  c     = (Color)  row[2];

            PdfPCell card = new PdfPCell();
            card.setBackgroundColor(c);
            card.setPadding(10);
            card.setBorder(Rectangle.NO_BORDER);
            card.setHorizontalAlignment(Element.ALIGN_CENTER);

            Paragraph p = new Paragraph();
            p.add(new Chunk(label + "\n", new Font(f.bold(), 10, Font.NORMAL, Color.WHITE)));
            p.add(new Chunk(cnt + "건", new Font(f.bold(), 18, Font.NORMAL, Color.WHITE)));
            p.add(new Chunk("\n" + String.format("%.1f%%", cnt * 100.0 / total),
                    new Font(f.reg(), 9, Font.NORMAL, new Color(255, 255, 255, 180))));
            p.setAlignment(Element.ALIGN_CENTER);
            card.addElement(p);
            t.addCell(card);
        }
        return t;
    }

    // ── 2페이지: TOP 5 ────────────────────────────────────────────────────

    private void writeTop5Page(Document doc, PdfWriter writer,
                               FontSet f, AnalysisResultView result) throws DocumentException {
        doc.add(headerBanner(f, "핵심 취약점 TOP 5", "탐지 빈도 기준 상위 취약점 유형", 18, 10));
        doc.add(space(8));

        Map<String, Long> ruleMap = result.getFindings().stream()
                .collect(Collectors.groupingBy(
                        v -> v.getFinding().getRuleId() + " — " + v.getFinding().getRuleName(),
                        Collectors.counting()));

        List<Map.Entry<String, Long>> top5 = ruleMap.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5).collect(Collectors.toList());

        long maxCnt = top5.isEmpty() ? 1 : top5.get(0).getValue();
        Color[] rankColors = {
            new Color(59, 130, 246), new Color(16, 185, 129),
            new Color(245, 158, 11), new Color(239, 68, 68), new Color(139, 92, 246)
        };

        for (int i = 0; i < top5.size(); i++) {
            var e = top5.get(i);
            Color bc = rankColors[i % rankColors.length];

            PdfPTable row = tbl(3, new float[]{0.5f, 4f, 1.5f});
            row.setSpacingBefore(6);
            row.setSpacingAfter(0);

            // 순위 배지
            PdfPCell rank = new PdfPCell(phrase(String.valueOf(i + 1), f.bold(), 18, Color.WHITE));
            rank.setBackgroundColor(bc);
            rank.setHorizontalAlignment(Element.ALIGN_CENTER);
            rank.setVerticalAlignment(Element.ALIGN_MIDDLE);
            rank.setPadding(8);
            rank.setBorder(Rectangle.NO_BORDER);
            addCell(row, rank);

            // 규칙명 + 바
            PdfPCell info = new PdfPCell();
            info.setBorder(Rectangle.NO_BORDER);
            info.setBackgroundColor(GRAY_BG);
            info.setPadding(6);
            info.addElement(new Paragraph(e.getKey(), new Font(f.bold(), 11, Font.NORMAL, SLATE)));
            info.addElement(barChart(e.getValue(), maxCnt, bc));
            addCell(row, info);

            // 건수
            PdfPCell cnt = new PdfPCell(phrase(e.getValue() + "건", f.bold(), 14, bc));
            cnt.setBackgroundColor(GRAY_BG);
            cnt.setHorizontalAlignment(Element.ALIGN_CENTER);
            cnt.setVerticalAlignment(Element.ALIGN_MIDDLE);
            cnt.setBorder(Rectangle.NO_BORDER);
            cnt.setPadding(8);
            addCell(row, cnt);

            doc.add(row);
        }

        // 부가 통계
        doc.add(space(14));
        doc.add(sectionTitle(f, "분석 요약"));
        long uRules = result.getFindings().stream().map(v -> v.getFinding().getRuleId()).distinct().count();
        long uFiles = result.getFindings().stream().map(v -> v.getFinding().getFilePath()).distinct().count();

        PdfPTable sumTbl = tbl(2, new float[]{1, 1});
        addCell(sumTbl, metaCell(f, "탐지된 고유 규칙 수", uRules + "개"));
        addCell(sumTbl, metaCell(f, "취약점 발견 파일 수", uFiles + "개"));
        addCell(sumTbl, metaCell(f, "전체 탐지 건수",     result.getTotalFindings() + "건"));
        addCell(sumTbl, metaCell(f, "분석 Java 파일 수",  result.getTotalFiles() + "개"));
        doc.add(sumTbl);
    }

    // ── 3페이지~: 상세 목록 ──────────────────────────────────────────────

    private void writeDetailsPages(Document doc, FontSet f, AnalysisResultView result)
            throws DocumentException {
        doc.add(headerBanner(f, "상세 취약점 목록",
                "총 " + result.getTotalFindings() + "건  (위험도 순 정렬)", 18, 10));

        List<FindingView> views = result.getFindings();
        for (int i = 0; i < views.size(); i++) {
            doc.add(space(8));
            writeFinding(doc, f, i + 1, views.get(i));
        }
    }

    private void writeFinding(Document doc, FontSet f, int num, FindingView view)
            throws DocumentException {
        Finding finding = view.getFinding();
        Color sc = sevColor(finding.getSeverity());

        // ── 헤더 바 ────────────────────────────────────────────────────
        PdfPTable hdr = tbl(2, new float[]{8, 2});
        hdr.setSpacingBefore(0);

        String title = String.format("[%d] %s — %s", num, finding.getRuleId(), finding.getRuleName());
        PdfPCell titleCell = new PdfPCell(phrase(title, f.bold(), 11, Color.WHITE));
        titleCell.setBackgroundColor(sc);
        titleCell.setPadding(8);
        titleCell.setBorder(Rectangle.NO_BORDER);
        addCell(hdr, titleCell);

        PdfPCell sevCell = new PdfPCell(phrase(finding.getSeverity().name() + "\n(" + finding.getSeverity().toKorean() + ")",
                f.bold(), 9, sc));
        sevCell.setBackgroundColor(Color.WHITE);
        sevCell.setHorizontalAlignment(Element.ALIGN_CENTER);
        sevCell.setVerticalAlignment(Element.ALIGN_MIDDLE);
        sevCell.setBorder(Rectangle.NO_BORDER);
        sevCell.setBorderWidthLeft(1);
        sevCell.setBorderColorLeft(sc);
        addCell(hdr, sevCell);
        doc.add(hdr);

        // ── 메타 정보 ───────────────────────────────────────────────────
        PdfPTable meta = tbl(4, new float[]{1.2f, 2.3f, 1.2f, 2.3f});
        meta.setSpacingBefore(0);

        String shortPath = shortPath(finding.getFilePath());
        addCell(meta, labelCell(f, "파일"));
        addCell(meta, valueCell(f, shortPath));
        addCell(meta, labelCell(f, "라인"));
        addCell(meta, valueCell(f, String.valueOf(finding.getLineNumber())));

        String cwes = finding.getCweIds() != null ? String.join(", ", finding.getCweIds()) : "-";
        addCell(meta, labelCell(f, "CWE"));
        addCell(meta, valueCell(f, cwes));
        addCell(meta, labelCell(f, "가이드"));
        addCell(meta, valueCell(f, finding.getGuideRef() != null ? finding.getGuideRef() : "-"));
        doc.add(meta);

        // ── 탐지 근거 ───────────────────────────────────────────────────
        if (finding.getDescription() != null && !finding.getDescription().isBlank()) {
            doc.add(subLabel(f, "탐지 근거"));
            Paragraph desc = new Paragraph(finding.getDescription(),
                    new Font(f.reg(), 9, Font.NORMAL, SLATE));
            desc.setSpacingBefore(2);
            desc.setSpacingAfter(4);
            doc.add(desc);
        }

        // ── 취약 코드 ───────────────────────────────────────────────────
        if (finding.getVulnerableCode() != null && !finding.getVulnerableCode().isBlank()) {
            doc.add(subLabel(f, "취약 코드"));
            doc.add(codeBlock(f, finding.getVulnerableCode(), new Color(239, 68, 68)));
        }

        // ── 권고 수정 코드 ─────────────────────────────────────────────
        String remCode = finding.getRemediatedCode();
        if ((remCode == null || remCode.isBlank()) && view.getRemediation() != null) {
            remCode = view.getRemediation().getRemediatedCode();
        }
        if (remCode != null && !remCode.isBlank()) {
            doc.add(subLabel(f, "권고 수정 코드"));
            doc.add(codeBlock(f, remCode, new Color(34, 197, 94)));
        }

        // ── 코드 예시 (보안 가이드) ────────────────────────────────────
        SecurityRule rule = ruleMap.get(finding.getRuleId());
        if (rule != null && rule.getCodeExamples() != null) {
            SecurityRule.CodeExamples ex = rule.getCodeExamples();
            boolean hasBad  = ex.getBad()  != null && !ex.getBad().isBlank();
            boolean hasGood = ex.getGood() != null && !ex.getGood().isBlank();
            if (hasBad || hasGood) {
                doc.add(subLabel(f, "코드 예시 (보안 가이드)"));
                if (hasBad) {
                    doc.add(codeExampleLabel(f, "[취약 코드 예시]", new Color(239, 68, 68)));
                    doc.add(codeBlock(f, ex.getBad(), new Color(239, 68, 68)));
                }
                if (hasGood) {
                    doc.add(codeExampleLabel(f, "[안전한 수정 예시]", new Color(22, 163, 74)));
                    doc.add(codeBlock(f, ex.getGood(), new Color(22, 163, 74)));
                }
            }
        }

        // ── 구분선 ────────────────────────────────────────────────────
        doc.add(divider());
    }

    // ── 공통 컴포넌트 ─────────────────────────────────────────────────────

    private PdfPTable headerBanner(FontSet f, String title, String sub, float titleSz, float padding) {
        PdfPTable t = tbl(1, new float[]{1});
        t.setSpacingAfter(0);

        PdfPCell c = new PdfPCell();
        c.setBackgroundColor(NAVY);
        c.setPadding(padding + 5);
        c.setBorder(Rectangle.NO_BORDER);

        Paragraph p = new Paragraph();
        p.add(new Chunk(title + "\n", new Font(f.bold(), titleSz, Font.NORMAL, Color.WHITE)));
        p.add(new Chunk(sub, new Font(f.reg(), 10, Font.NORMAL, LAVENDER)));
        p.setAlignment(Element.ALIGN_LEFT);
        c.addElement(p);

        addCell(t, c);
        return t;
    }

    private PdfPTable sectionTitle(FontSet f, String title) {
        PdfPTable t = tbl(1, new float[]{1});
        t.setSpacingBefore(2);
        t.setSpacingAfter(4);

        PdfPCell c = new PdfPCell();
        c.setBorderWidthBottom(1.5f);
        c.setBorderColorBottom(NAVY);
        c.setBorderWidthTop(0);
        c.setBorderWidthLeft(0);
        c.setBorderWidthRight(0);
        c.setPaddingBottom(5);
        c.addElement(new Paragraph(title, new Font(f.bold(), 12, Font.NORMAL, NAVY)));
        addCell(t, c);
        return t;
    }

    private Element subLabel(FontSet f, String label) {
        PdfPTable t = tbl(1, new float[]{1});
        t.setSpacingBefore(4);
        t.setSpacingAfter(2);
        PdfPCell c = new PdfPCell();
        c.setBorderWidthLeft(3);
        c.setBorderColorLeft(NAVY);
        c.setBorderWidthTop(0);
        c.setBorderWidthRight(0);
        c.setBorderWidthBottom(0);
        c.setPaddingLeft(6);
        c.setPaddingTop(2);
        c.setPaddingBottom(2);
        c.addElement(new Paragraph(label, new Font(f.bold(), 9, Font.NORMAL, SLATE)));
        addCell(t, c);
        return t;
    }

    private Element codeExampleLabel(FontSet f, String label, Color accent) {
        PdfPTable t = tbl(1, new float[]{1});
        t.setSpacingBefore(4);
        t.setSpacingAfter(0);
        PdfPCell c = new PdfPCell();
        c.setBorder(Rectangle.NO_BORDER);
        c.setBorderWidthLeft(3);
        c.setBorderColorLeft(accent);
        c.setBackgroundColor(new Color(
                Math.min(accent.getRed()   + 200, 255),
                Math.min(accent.getGreen() + 200, 255),
                Math.min(accent.getBlue()  + 200, 255)));
        c.setPaddingLeft(6);
        c.setPaddingTop(3);
        c.setPaddingBottom(3);
        c.addElement(new Paragraph(label, new Font(f.bold(), 8, Font.NORMAL, accent)));
        addCell(t, c);
        return t;
    }

    private PdfPTable codeBlock(FontSet f, String code, Color accentColor) {
        // 상단 강조선 + 배경색 블록
        PdfPTable outer = tbl(1, new float[]{1});
        outer.setSpacingBefore(0);
        outer.setSpacingAfter(4);

        PdfPCell c = new PdfPCell();
        c.setBackgroundColor(GRAY_BG);
        c.setBorder(Rectangle.NO_BORDER);
        c.setBorderWidthTop(2);
        c.setBorderColorTop(accentColor);
        c.setPadding(6);

        Font monoFont = new Font(f.mono(), 8, Font.NORMAL, SLATE);
        String[] lines = code.split("\n");
        int shown = Math.min(lines.length, 20);
        Paragraph codePara = new Paragraph();
        codePara.setLeading(12);
        for (int i = 0; i < shown; i++) {
            String line = lines[i];
            if (line.length() > 110) line = line.substring(0, 107) + "...";
            codePara.add(new Chunk(line + "\n", monoFont));
        }
        if (lines.length > shown) {
            codePara.add(new Chunk("... (" + (lines.length - shown) + "줄 생략)", monoFont));
        }
        c.addElement(codePara);
        addCell(outer, c);
        return outer;
    }

    private PdfPTable divider() {
        PdfPTable t = tbl(1, new float[]{1});
        t.setSpacingBefore(4);
        t.setSpacingAfter(0);
        PdfPCell c = new PdfPCell();
        c.setFixedHeight(1);
        c.setBackgroundColor(GRAY_LINE);
        c.setBorder(Rectangle.NO_BORDER);
        addCell(t, c);
        return t;
    }

    private PdfPTable barChart(long value, long maxValue, Color barColor) {
        if (maxValue <= 0) maxValue = 1;
        float pct = (float) value / maxValue;
        int filled = Math.max(1, Math.round(pct * 100));
        int empty  = 100 - filled;

        PdfPTable bar = new PdfPTable(empty > 0 ? 2 : 1);
        try { bar.setWidths(empty > 0 ? new float[]{filled, empty} : new float[]{100}); }
        catch (DocumentException ignored) {}
        bar.setWidthPercentage(100);

        PdfPCell fc = new PdfPCell();
        fc.setBackgroundColor(barColor);
        fc.setFixedHeight(10);
        fc.setBorder(Rectangle.NO_BORDER);
        bar.addCell(fc);

        if (empty > 0) {
            PdfPCell ec = new PdfPCell();
            ec.setBackgroundColor(GRAY_LINE);
            ec.setFixedHeight(10);
            ec.setBorder(Rectangle.NO_BORDER);
            bar.addCell(ec);
        }
        return bar;
    }

    // ── 셀 팩토리 헬퍼 ───────────────────────────────────────────────────

    private Phrase phrase(String text, BaseFont bf, float size, Color color) {
        return new Phrase(text, new Font(bf, size, Font.NORMAL, color));
    }

    private Font f(BaseFont bf, float size, Color c) {
        return new Font(bf, size, Font.NORMAL, c);
    }

    private PdfPCell cell(Phrase p, Color bg, float padding, int border) {
        PdfPCell c = new PdfPCell(p);
        c.setBackgroundColor(bg);
        c.setPadding(padding);
        c.setBorder(border);
        return c;
    }

    private PdfPCell noBorderCell(Phrase p, float padding, int unused) {
        PdfPCell c = new PdfPCell(p);
        c.setBorder(Rectangle.NO_BORDER);
        c.setPadding(padding);
        c.setVerticalAlignment(Element.ALIGN_MIDDLE);
        return c;
    }

    private PdfPCell noBorderCell(PdfPTable inner, float padding, int unused) {
        PdfPCell c = new PdfPCell(inner);
        c.setBorder(Rectangle.NO_BORDER);
        c.setPadding(padding);
        c.setVerticalAlignment(Element.ALIGN_MIDDLE);
        return c;
    }

    private PdfPCell labelCell(FontSet f, String text) {
        PdfPCell c = new PdfPCell(phrase(text, f.bold(), 9, NAVY));
        c.setBackgroundColor(new Color(241, 245, 249));
        c.setPadding(5);
        c.setBorder(Rectangle.NO_BORDER);
        return c;
    }

    private PdfPCell valueCell(FontSet f, String text) {
        PdfPCell c = new PdfPCell(phrase(text, f.reg(), 9, SLATE));
        c.setBackgroundColor(GRAY_BG);
        c.setPadding(5);
        c.setBorder(Rectangle.NO_BORDER);
        return c;
    }

    private PdfPCell metaCell(FontSet f, String label, String value) {
        PdfPCell c = new PdfPCell();
        c.setBackgroundColor(GRAY_BG);
        c.setPadding(8);
        c.setBorder(Rectangle.NO_BORDER);
        Paragraph p = new Paragraph();
        p.add(new Chunk(label + "\n", new Font(f.bold(), 9, Font.NORMAL, GRAY_DARK)));
        p.add(new Chunk(value, new Font(f.bold(), 13, Font.NORMAL, NAVY)));
        c.addElement(p);
        return c;
    }

    private PdfPTable tbl(int cols, float[] widths) {
        PdfPTable t = new PdfPTable(cols);
        t.setWidthPercentage(100);
        try { t.setWidths(widths); } catch (DocumentException ignored) {}
        t.setSpacingBefore(0);
        t.setSpacingAfter(0);
        return t;
    }

    private void addCell(PdfPTable t, PdfPCell c) {
        t.addCell(c);
    }

    private Paragraph space(float h) {
        Paragraph p = new Paragraph(" ");
        p.setSpacingBefore(0);
        p.setSpacingAfter(h);
        return p;
    }

    private PdfPTable dividerLine() {
        return divider();
    }

    // ── 헬퍼 ─────────────────────────────────────────────────────────────

    private Color sevColor(Finding.Severity s) {
        return switch (s) {
            case CRITICAL -> new Color(220, 38, 38);
            case HIGH     -> new Color(234, 88, 12);
            case MEDIUM   -> new Color(202, 138, 4);
            case LOW      -> new Color(100, 116, 139);
        };
    }

    private String shortPath(String path) {
        if (path == null) return "";
        int i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        // 마지막 슬래시 기준으로 앞 일부 + 파일명
        String fileName = i >= 0 ? path.substring(i + 1) : path;
        String parent   = i >= 0 ? path.substring(0, i) : "";
        int j = Math.max(parent.lastIndexOf('/'), parent.lastIndexOf('\\'));
        String parentDir = j >= 0 ? parent.substring(j + 1) : parent;
        return parentDir.isEmpty() ? fileName : parentDir + "/" + fileName;
    }

    // ── FontSet 접근자 (record) ─────────────────────────────────────────
    // Renderer가 FontSet record를 사용하므로 inner 확장
    private BaseFont baseFont(FontSet f, boolean bold) {
        return bold ? f.bold() : f.reg();
    }
}
