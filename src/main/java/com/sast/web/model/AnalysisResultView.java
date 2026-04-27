package com.sast.web.model;

import java.util.List;

/**
 * 분석 결과 대시보드용 뷰 모델
 */
public class AnalysisResultView {

    private final String         uploadedFileName;
    private final int            totalFiles;
    private final List<FindingView> findings;

    public AnalysisResultView(String uploadedFileName, int totalFiles, List<FindingView> findings) {
        this.uploadedFileName = uploadedFileName;
        this.totalFiles       = totalFiles;
        this.findings         = findings;
    }

    public String            getUploadedFileName() { return uploadedFileName; }
    public int               getTotalFiles()       { return totalFiles; }
    public List<FindingView> getFindings()         { return findings; }
    public int               getTotalFindings()    { return findings.size(); }

    public long getCriticalCount() {
        return findings.stream()
                .filter(v -> v.getFinding().getSeverity() == com.sast.model.Finding.Severity.CRITICAL)
                .count();
    }

    public long getHighCount() {
        return findings.stream()
                .filter(v -> v.getFinding().getSeverity() == com.sast.model.Finding.Severity.HIGH)
                .count();
    }

    public long getMediumCount() {
        return findings.stream()
                .filter(v -> v.getFinding().getSeverity() == com.sast.model.Finding.Severity.MEDIUM)
                .count();
    }

    public long getLowCount() {
        return findings.stream()
                .filter(v -> v.getFinding().getSeverity() == com.sast.model.Finding.Severity.LOW)
                .count();
    }
}
