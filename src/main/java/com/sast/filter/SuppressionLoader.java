package com.sast.filter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

/**
 * sast-suppressions.json 로더
 *
 * 탐색 순서:
 *   1. 인자로 받은 외부 파일 경로 (CLI: 작업 디렉터리, 웹: Spring classpath root)
 *   2. 클래스패스 내 sast-suppressions.json
 */
public class SuppressionLoader {

    private static final Logger log = LoggerFactory.getLogger(SuppressionLoader.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static List<SuppressionRule> load(String externalPath) {
        if (externalPath != null) {
            File f = new File(externalPath);
            if (f.exists() && f.isFile()) {
                try {
                    Data data = MAPPER.readValue(f, Data.class);
                    log.info("[Suppressions] 외부 파일 로드: {} ({}건)", f.getAbsolutePath(), data.suppressions.size());
                    return convert(data);
                } catch (IOException e) {
                    log.warn("[Suppressions] 외부 파일 파싱 실패: {}", e.getMessage());
                }
            }
        }

        // 클래스패스 폴백
        try (InputStream is = SuppressionLoader.class.getClassLoader()
                .getResourceAsStream("sast-suppressions.json")) {
            if (is == null) return List.of();
            Data data = MAPPER.readValue(is, Data.class);
            log.info("[Suppressions] 클래스패스 로드 ({}건)", data.suppressions.size());
            return convert(data);
        } catch (IOException e) {
            log.warn("[Suppressions] classpath 로드 실패: {}", e.getMessage());
            return List.of();
        }
    }

    private static List<SuppressionRule> convert(Data data) {
        if (data == null || data.suppressions == null) return List.of();
        return data.suppressions.stream()
                .map(r -> new SuppressionRule(r.file, r.ruleId, r.line, r.reason))
                .toList();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class Data {
        public List<RuleDto> suppressions = new ArrayList<>();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class RuleDto {
        public String  file;
        public String  ruleId;
        public Integer line;
        public String  reason;
    }
}
