package com.sast.engine.rules;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * security-rules.json을 클래스패스에서 로드하여 SecurityRule 목록으로 반환합니다.
 * JSON 내 // 주석을 허용합니다 (Jackson ALLOW_COMMENTS).
 */
public class RuleLoader {

    private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);

    private RuleLoader() {}

    /**
     * 클래스패스 리소스에서 보안 규칙을 로드합니다.
     *
     * @param resourceName 클래스패스 상의 JSON 파일명 (예: "security-rules.json")
     * @return 로드된 SecurityRule 목록
     * @throws RuntimeException 파일을 찾을 수 없거나 파싱에 실패한 경우
     */
    public static List<SecurityRule> loadFromClasspath(String resourceName) {
        ObjectMapper mapper = new ObjectMapper();
        // security-rules.json에 // 스타일 주석이 포함되어 있어 ALLOW_COMMENTS 필수
        mapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        try (InputStream is = RuleLoader.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) {
                throw new RuntimeException("보안 규칙 파일을 찾을 수 없습니다: " + resourceName);
            }
            JsonNode root = mapper.readTree(is);
            JsonNode rulesNode = root.get("rules");
            if (rulesNode == null || !rulesNode.isArray()) {
                throw new RuntimeException("security-rules.json에 'rules' 배열이 없습니다.");
            }
            List<SecurityRule> rules = mapper.convertValue(
                    rulesNode,
                    new TypeReference<List<SecurityRule>>() {}
            );
            log.info("[RuleLoader] 보안 규칙 {}개 로드 완료 (출처: {})", rules.size(), resourceName);
            return rules;
        } catch (IOException e) {
            throw new RuntimeException("규칙 로드 실패: " + resourceName, e);
        }
    }
}
