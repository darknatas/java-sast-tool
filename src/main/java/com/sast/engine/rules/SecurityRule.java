package com.sast.engine.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

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
    private CodeExamples codeExamples;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CodeExamples {
        private String bad;
        private String good;

        public String getBad()  { return bad; }
        public String getGood() { return good; }

        public void setBad(String v)  { this.bad = v; }
        public void setGood(String v) { this.good = v; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Remediation {
        private String strategy;
        private String description;
        private String guideRef;
        private String remediationCode;

        @JsonProperty("bad_code")
        private String badCode;

        @JsonProperty("good_code")
        private String goodCode;

        public String getStrategy()        { return strategy; }
        public String getDescription()     { return description; }
        public String getGuideRef()        { return guideRef; }
        public String getRemediationCode() { return remediationCode; }
        public String getBadCode()         { return badCode; }
        public String getGoodCode()        { return goodCode; }

        public void setStrategy(String v)        { this.strategy = v; }
        public void setDescription(String v)     { this.description = v; }
        public void setGuideRef(String v)        { this.guideRef = v; }
        public void setRemediationCode(String v) { this.remediationCode = v; }
        public void setBadCode(String v)         { this.badCode = v; }
        public void setGoodCode(String v)        { this.goodCode = v; }
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

    public Remediation getRemediation()   { return remediation; }
    public CodeExamples getCodeExamples() { return codeExamples; }

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
    public void setRemediation(Remediation v)   { this.remediation = v; }
    public void setCodeExamples(CodeExamples v) { this.codeExamples = v; }
}
