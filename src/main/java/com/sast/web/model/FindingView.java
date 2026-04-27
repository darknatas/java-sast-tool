package com.sast.web.model;

import com.sast.model.Finding;
import com.sast.remediation.RemediationService;

/**
 * 웹 뷰용 DTO — Finding + RemediationResult를 하나로 묶어 Thymeleaf에 전달
 */
public class FindingView {

    private final Finding finding;
    private final RemediationService.RemediationResult remediation;

    public FindingView(Finding finding, RemediationService.RemediationResult remediation) {
        this.finding     = finding;
        this.remediation = remediation;
    }

    public Finding getFinding()                              { return finding; }
    public RemediationService.RemediationResult getRemediation() { return remediation; }

    // 위험도별 Bootstrap 색상 클래스 반환 (Thymeleaf에서 직접 호출)
    public String getSeverityBadgeClass() {
        return switch (finding.getSeverity()) {
            case CRITICAL -> "badge bg-danger";
            case HIGH     -> "badge bg-warning text-dark";
            case MEDIUM   -> "badge bg-info text-dark";
            case LOW      -> "badge bg-secondary";
        };
    }

    public String getSeverityCardClass() {
        return switch (finding.getSeverity()) {
            case CRITICAL -> "border-danger";
            case HIGH     -> "border-warning";
            case MEDIUM   -> "border-info";
            case LOW      -> "border-secondary";
        };
    }

    public String getSeverityKorean() {
        return finding.getSeverity().toKorean();
    }

    // 파일 경로를 짧게 표시 (절대경로에서 파일명만 추출)
    public String getShortFilePath() {
        String path = finding.getFilePath();
        if (path == null) return "";
        int lastSep = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return lastSep >= 0 ? path.substring(lastSep + 1) : path;
    }
}
