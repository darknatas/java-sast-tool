package com.sast.engine.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Collections;
import java.util.List;

/**
 * 보안 규칙 DTO — security-rules.json에서 역직렬화됩니다.
 * 직접 new SecurityRule()으로 생성하지 마세요; RuleLoader를 통해 사용하세요.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityRule {

    private String ruleId;
    private String part;
    private String section;
    private String name;

    private List<String> cwe;

    private String severity;
    private String phase;
    private boolean taintAnalysis;
    private boolean sequenceAnalysis;

    private List<String> sources;
    private List<String> sinks;
    private List<String> sanitizers;
    private List<String> dangerousPatterns;

    private Remediation remediation;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Remediation {
        private String strategy;
        private String description;
        private String guideRef;

        public String getStrategy()    { return strategy; }
        public String getDescription() { return description; }
        public String getGuideRef()    { return guideRef; }

        public void setStrategy(String v)    { this.strategy = v; }
        public void setDescription(String v) { this.description = v; }
        public void setGuideRef(String v)    { this.guideRef = v; }
    }

    // ── Getters ──────────────────────────────────────────────────────────

    public String getRuleId()    { return ruleId; }
    public String getPart()      { return part; }
    public String getSection()   { return section; }
    public String getName()      { return name; }
    public String getSeverity()  { return severity; }
    public String getPhase()     { return phase; }
    public boolean isTaintAnalysis()    { return taintAnalysis; }
    public boolean isSequenceAnalysis() { return sequenceAnalysis; }

    public List<String> getCwe()             { return cwe != null ? cwe : Collections.emptyList(); }
    public List<String> getSources()         { return sources != null ? sources : Collections.emptyList(); }
    public List<String> getSinks()           { return sinks != null ? sinks : Collections.emptyList(); }
    public List<String> getSanitizers()      { return sanitizers != null ? sanitizers : Collections.emptyList(); }
    public List<String> getDangerousPatterns() { return dangerousPatterns != null ? dangerousPatterns : Collections.emptyList(); }

    public String getGuideRef() {
        return remediation != null ? remediation.getGuideRef() : "";
    }

    public Remediation getRemediation() { return remediation; }

    // ── Setters (Jackson 역직렬화용) ─────────────────────────────────────

    public void setRuleId(String v)      { this.ruleId = v; }
    public void setPart(String v)        { this.part = v; }
    public void setSection(String v)     { this.section = v; }
    public void setName(String v)        { this.name = v; }
    public void setCwe(List<String> v)   { this.cwe = v; }
    public void setSeverity(String v)    { this.severity = v; }
    public void setPhase(String v)       { this.phase = v; }
    public void setTaintAnalysis(boolean v)    { this.taintAnalysis = v; }
    public void setSequenceAnalysis(boolean v) { this.sequenceAnalysis = v; }
    public void setSources(List<String> v)  { this.sources = v; }
    public void setSinks(List<String> v)    { this.sinks = v; }
    public void setSanitizers(List<String> v) { this.sanitizers = v; }
    public void setDangerousPatterns(List<String> v) { this.dangerousPatterns = v; }
    public void setRemediation(Remediation v) { this.remediation = v; }
}
