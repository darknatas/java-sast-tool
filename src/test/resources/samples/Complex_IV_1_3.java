package com.example.storage;

import javax.servlet.http.HttpServletRequest;
import java.io.*;

/**
 * 기업용 문서관리시스템(DMS) — 멀티테넌트 첨부파일 서비스
 *
 * 스토리지 계층 구조:
 *   /data/tenants/{tenantId}/archive/{yearMon}/{docType}/{docId}/{version}/{filename}
 *
 * 설계 의도:
 *   - tenantId 기반 격리로 테넌트 간 파일 접근 차단
 *   - yearMon + docType 조합으로 대용량 파일 파티셔닝
 *   - version 관리로 동일 문서의 이력 보존
 *
 * 보안 리뷰 지적사항 (미조치):
 *   - 경로 구성 요소 전체가 외부 입력에서 직접 취득됨
 *   - getCanonicalPath() 검증 없이 FileInputStream 직접 생성
 *   - "../../../etc/passwd" 형태 경로 탈출 공격에 취약
 */
public class Complex_IV_1_3 {

    private static final String STORAGE_ROOT = "/data/tenants";
    private static final int    READ_TIMEOUT = 30_000;

    /**
     * 첨부파일 바이트 배열 반환 — 6단계 경로 조합 패턴
     *
     * 취약 지점: 6개 파라미터 모두 미검증으로 경로에 직접 삽입
     *   → tenantId: "../evil" 삽입 시 다른 테넌트 파일 접근
     *   → docId: "../../etc/passwd" 삽입 시 OS 파일 노출
     *   → filename: null byte 삽입(%00) 가능
     */
    public byte[] loadAttachmentBytes(HttpServletRequest request) throws Exception {

        // ① Source — 라우팅 파라미터 6개 (모두 외부 입력)
        String tenantId = request.getParameter("tenantId");  // 테넌트 식별자 (예: "corp-acme")
        String yearMon  = request.getParameter("yearMon");   // 연월 파티션 (예: "202401")
        String docType  = request.getParameter("docType");   // 문서 유형 (예: "contract")
        String docId    = request.getParameter("docId");     // 문서 번호 (예: "DOC-0042")
        String version  = request.getParameter("version");  // 버전 (예: "v2")
        String filename = request.getParameter("filename"); // 파일명 (예: "report.pdf")

        // ② Propagation 1단계 — 테넌트 루트 경로 (tenantId 오염)
        String tenantBase = STORAGE_ROOT + "/" + tenantId;                   // taint: tenantId

        // ③ Propagation 2단계 — 연월 아카이브 경로 (yearMon 합류)
        String archivePath = tenantBase + "/archive/" + yearMon;            // taint: tenantId + yearMon

        // ④ Propagation 3단계 — 문서 유형 + 번호 경로 (docType, docId 합류)
        String docBase = archivePath + "/" + docType + "/" + docId;         // taint: tenantId + yearMon + docType + docId

        // ⑤ Propagation 4단계 — 버전 디렉터리 (version 합류)
        String versionDir = docBase + "/" + version;                        // taint: 5개 파라미터 누적

        // ⑥ Propagation 5단계 — 최종 파일 경로 (filename 합류 → 모든 파라미터 오염)
        String fullPath = versionDir + "/" + filename;                      // taint: 6개 파라미터 전체

        // ⑦ Sink — 경로 정규화(getCanonicalPath) 없이 FileInputStream 직접 생성 (IV-1.3 탐지)
        FileInputStream fis = new FileInputStream(fullPath);   // SINK: IV-1.3 경로 조작
        byte[] content = fis.readAllBytes();
        fis.close();
        return content;
    }
}
