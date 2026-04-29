package com.sast.web;

import com.sast.report.PdfReportGenerator;
import com.sast.web.model.AnalysisResultView;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * SAST 웹 컨트롤러 — ZIP 업로드 → 분석 → 결과 대시보드 + PDF 다운로드
 */
@Controller
public class SastWebController {

    private static final Logger log = LoggerFactory.getLogger(SastWebController.class);

    // 세션 키: 마지막 분석 결과 저장용 (PDF 다운로드에 재사용)
    private static final String SESSION_KEY_RESULT = "lastAnalysisResult";

    private final SastAnalysisService analysisService;
    private final PdfReportGenerator  pdfReportGenerator;

    public SastWebController(SastAnalysisService analysisService,
                             PdfReportGenerator pdfReportGenerator) {
        this.analysisService    = analysisService;
        this.pdfReportGenerator = pdfReportGenerator;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    /**
     * ZIP 업로드 → SAST 분석 → 결과 뷰 반환
     * 분석 결과를 세션에도 저장하여 /report/download 엔드포인트에서 재사용
     */
    @PostMapping("/analyze")
    public String analyze(
            @RequestParam("zipFile") MultipartFile zipFile,
            HttpSession session,
            Model model,
            RedirectAttributes redirectAttributes) {

        // 파일 유효성 검사 (IV-1.6)
        if (zipFile.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "파일을 선택해 주세요.");
            return "redirect:/";
        }

        String originalName = zipFile.getOriginalFilename() != null
                ? zipFile.getOriginalFilename().toLowerCase() : "";
        if (!originalName.endsWith(".zip") && !originalName.endsWith(".7z")) {
            redirectAttributes.addFlashAttribute("error", "ZIP 또는 7z 형식의 파일만 업로드할 수 있습니다.");
            return "redirect:/";
        }

        try {
            log.info("[SAST-Web] 분석 요청: {}, 크기: {} bytes",
                    zipFile.getOriginalFilename(), zipFile.getSize());
            AnalysisResultView result = analysisService.analyze(zipFile);

            // 세션 저장 — PDF 다운로드 시 재사용 (단일 사용자 도구 기준, 세션 메모리)
            session.setAttribute(SESSION_KEY_RESULT, result);
            model.addAttribute("result", result);
            model.addAttribute("hasPdfDownload", true);
            return "results";

        } catch (SecurityException e) {
            log.warn("[SAST-Web] 보안 위반 업로드 차단: {}", e.getMessage());
            redirectAttributes.addFlashAttribute("error", "보안 검사에 실패했습니다: " + e.getMessage());
            return "redirect:/";
        } catch (Exception e) {
            log.error("[SAST-Web] 분석 중 오류: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error", "분석 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
            return "redirect:/";
        }
    }

    /**
     * 마지막 분석 결과를 PDF로 다운로드
     * 세션에 저장된 AnalysisResultView를 PDFBox로 변환하여 반환
     * 세션 없거나 생성 실패 시 → 홈으로 리다이렉트 + 플래시 메시지
     *
     * GET /report/download
     */
    @GetMapping("/report/download")
    public Object downloadPdf(HttpSession session, RedirectAttributes redirectAttributes) {
        AnalysisResultView result = (AnalysisResultView) session.getAttribute(SESSION_KEY_RESULT);
        if (result == null) {
            log.warn("[SAST-Web] PDF 다운로드 요청 — 세션에 분석 결과 없음");
            redirectAttributes.addFlashAttribute("error",
                    "분석 세션이 만료되었습니다. ZIP 파일을 다시 업로드하여 분석을 실행해 주세요.");
            return "redirect:/";
        }

        try {
            log.info("[SAST-Web] PDF 리포트 생성 시작 — {}건", result.getTotalFindings());
            byte[] pdf = pdfReportGenerator.generate(result);
            log.info("[SAST-Web] PDF 생성 완료 — {}KB", pdf.length / 1024);

            String filename = "sast-report-" + result.getUploadedFileName().replaceAll("[^a-zA-Z0-9._-]", "_") + ".pdf";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(pdf);

        } catch (Exception e) {
            log.error("[SAST-Web] PDF 생성 실패: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("error",
                    "PDF 생성 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
            return "redirect:/";
        }
    }
}
