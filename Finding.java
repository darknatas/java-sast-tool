package com.sast.model;

import java.util.List;

/**
 * 분석 결과 단위 모델
 * PDF 기준: 소프트웨어 보안약점 진단가이드(2021) PART4
 */
public class Finding {

    /** 보안약점 규칙 ID (예: IV-1.1) */
    private String ruleId;

    /** 약점명 (예: SQL 삽입) */
    private String ruleName;

    /** 위험도: CRITICAL / HIGH / MEDIUM / LOW */
    private Severity severity;

    /** 분석 대상 파일명 */
    private String filePath;

    /** 취약 코드가 발견된 라인 번호 */
    private int lineNumber;

    /** 취약한 원본 코드 스니펫 */
    private String vulnerableCode;

    /** 탐지 근거 설명 */
    private String description;

    /** 오염 흐름 경로 (Source → Propagator → Sink) */
    private List<TaintFlow> taintFlows;

    /** 권고 수정 코드 */
    private String remediatedCode;

    /** 가이드 참조 페이지 */
    private String guideRef;

    /** CWE 번호 목록 */
    private List<String> cweIds;

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW;

        public String toKorean() {
            return switch (this) {
                case CRITICAL -> "치명";
                case HIGH     -> "높음";
                case MEDIUM   -> "중간";
                case LOW      -> "낮음";
            };
        }
    }

    // ── 내부 클래스: 탐지된 Taint 흐름 ──────────────────────────

    public static class TaintFlow {
        /** Source: 오염 입력 발생 지점 */
        private String sourceExpression;
        private int    sourceLine;

        /** Propagator: 오염 값이 전달되는 변수들 */
        private List<String> propagators;

        /** Sink: 취약점 발생 지점 */
        private String sinkExpression;
        private int    sinkLine;

        public TaintFlow(String sourceExpression, int sourceLine,
                         List<String> propagators,
                         String sinkExpression, int sinkLine) {
            this.sourceExpression = sourceExpression;
            this.sourceLine       = sourceLine;
            this.propagators      = propagators;
            this.sinkExpression   = sinkExpression;
            this.sinkLine         = sinkLine;
        }

        @Override
        public String toString() {
            return String.format("[Source L%d: %s] → [Propagators: %s] → [Sink L%d: %s]",
                    sourceLine, sourceExpression, propagators, sinkLine, sinkExpression);
        }

        // getters
        public String getSourceExpression() { return sourceExpression; }
        public int    getSourceLine()       { return sourceLine; }
        public List<String> getPropagators(){ return propagators; }
        public String getSinkExpression()   { return sinkExpression; }
        public int    getSinkLine()         { return sinkLine; }
    }

    // ── Builder ─────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private final Finding f = new Finding();

        public Builder ruleId(String v)          { f.ruleId = v;          return this; }
        public Builder ruleName(String v)         { f.ruleName = v;        return this; }
        public Builder severity(Severity v)       { f.severity = v;        return this; }
        public Builder filePath(String v)         { f.filePath = v;        return this; }
        public Builder lineNumber(int v)          { f.lineNumber = v;      return this; }
        public Builder vulnerableCode(String v)   { f.vulnerableCode = v;  return this; }
        public Builder description(String v)      { f.description = v;     return this; }
        public Builder taintFlows(List<TaintFlow> v) { f.taintFlows = v;  return this; }
        public Builder remediatedCode(String v)   { f.remediatedCode = v;  return this; }
        public Builder guideRef(String v)         { f.guideRef = v;        return this; }
        public Builder cweIds(List<String> v)     { f.cweIds = v;          return this; }
        public Finding build()                    { return f; }
    }

    // ── Getters ──────────────────────────────────────────────────

    public String getRuleId()           { return ruleId; }
    public String getRuleName()         { return ruleName; }
    public Severity getSeverity()       { return severity; }
    public String getFilePath()         { return filePath; }
    public int getLineNumber()          { return lineNumber; }
    public String getVulnerableCode()   { return vulnerableCode; }
    public String getDescription()      { return description; }
    public List<TaintFlow> getTaintFlows() { return taintFlows; }
    public String getRemediatedCode()   { return remediatedCode; }
    public String getGuideRef()         { return guideRef; }
    public List<String> getCweIds()     { return cweIds; }
}
