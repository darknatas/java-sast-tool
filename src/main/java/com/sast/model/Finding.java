package com.sast.model;

import java.util.List;

/**
 * 분석 결과 단위 모델 — 불변(immutable), Builder 패턴으로만 생성
 * 기준: 소프트웨어 보안약점 진단가이드(2021) PART4
 */
public class Finding {

    private String ruleId;
    private String ruleName;
    private Severity severity;
    private String filePath;
    private int lineNumber;
    private String vulnerableCode;
    private String description;
    private List<TaintFlow> taintFlows;
    private String remediatedCode;
    private String guideRef;
    private List<String> cweIds;

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW;

        public String toKorean() {
            if (this == CRITICAL) return "치명";
            if (this == HIGH)     return "높음";
            if (this == MEDIUM)   return "중간";
            return "낮음";
        }
    }

    // ── TaintFlow ────────────────────────────────────────────────────────

    public static class TaintFlow {
        private final String sourceExpression;
        private final int    sourceLine;
        private final List<String> propagators;
        private final String sinkExpression;
        private final int    sinkLine;

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

        public String getSourceExpression() { return sourceExpression; }
        public int    getSourceLine()       { return sourceLine; }
        public List<String> getPropagators(){ return propagators; }
        public String getSinkExpression()   { return sinkExpression; }
        public int    getSinkLine()         { return sinkLine; }
    }

    // ── Builder ──────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private final Finding f = new Finding();

        public Builder ruleId(String v)             { f.ruleId = v;         return this; }
        public Builder ruleName(String v)            { f.ruleName = v;       return this; }
        public Builder severity(Severity v)          { f.severity = v;       return this; }
        public Builder filePath(String v)            { f.filePath = v;       return this; }
        public Builder lineNumber(int v)             { f.lineNumber = v;     return this; }
        public Builder vulnerableCode(String v)      { f.vulnerableCode = v; return this; }
        public Builder description(String v)         { f.description = v;    return this; }
        public Builder taintFlows(List<TaintFlow> v) { f.taintFlows = v;    return this; }
        public Builder remediatedCode(String v)      { f.remediatedCode = v; return this; }
        public Builder guideRef(String v)            { f.guideRef = v;       return this; }
        public Builder cweIds(List<String> v)        { f.cweIds = v;         return this; }
        public Finding build()                       { return f; }
    }

    // ── Getters ──────────────────────────────────────────────────────────

    public String getRuleId()              { return ruleId; }
    public String getRuleName()            { return ruleName; }
    public Severity getSeverity()          { return severity; }
    public String getFilePath()            { return filePath; }
    public int getLineNumber()             { return lineNumber; }
    public String getVulnerableCode()      { return vulnerableCode; }
    public String getDescription()         { return description; }
    public List<TaintFlow> getTaintFlows() { return taintFlows; }
    public String getRemediatedCode()      { return remediatedCode; }
    public String getGuideRef()            { return guideRef; }
    public List<String> getCweIds()        { return cweIds; }
}
