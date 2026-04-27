package com.sast.web;

import com.sast.web.model.AnalysisResultView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * SAST 웹 컨트롤러 — ZIP 업로드 → 분석 → 결과 대시보드
 */
@Controller
public class SastWebController {

    private static final Logger log = LoggerFactory.getLogger(SastWebController.class);

    private final SastAnalysisService analysisService;

    public SastWebController(SastAnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(
            @RequestParam("zipFile") MultipartFile zipFile,
            Model model,
            RedirectAttributes redirectAttributes) {

        // 파일 유효성 검사 (IV-1.6)
        if (zipFile.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "ZIP 파일을 선택해 주세요.");
            return "redirect:/";
        }

        String originalName = zipFile.getOriginalFilename() != null
                ? zipFile.getOriginalFilename().toLowerCase() : "";
        if (!originalName.endsWith(".zip") && !originalName.endsWith(".7z")) {
            redirectAttributes.addFlashAttribute("error", "ZIP 또는 7z 형식의 파일만 업로드할 수 있습니다.");
            return "redirect:/";
        }

        try {
            log.info("[SAST-Web] 분석 요청: {}, 크기: {} bytes", zipFile.getOriginalFilename(), zipFile.getSize());
            AnalysisResultView result = analysisService.analyze(zipFile);
            model.addAttribute("result", result);
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
}
