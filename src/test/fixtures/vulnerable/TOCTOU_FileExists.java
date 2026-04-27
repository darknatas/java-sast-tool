package com.example.vulnerable;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * [취약 코드 샘플] 경쟁조건: 검사 시점과 사용 시점 (IV-3.1, CWE-367)
 *
 * exists() 검사 후 실제 파일 열기/삭제 사이 간격에
 * 다른 프로세스가 파일을 교체할 수 있음 (TOCTOU Race Condition).
 */
public class TOCTOU_FileExists {

    // 패턴 1: exists() 검사 후 FileInputStream — TOCTOU
    public void readUserFile(String fileName) throws IOException {
        File f = new File("/app/data/" + fileName);

        // [Check] 파일 존재 검사
        if (f.exists()) {
            // [Use] 검사와 열기 사이에 다른 프로세스가 f를 교체할 수 있음
            FileInputStream fis = new FileInputStream(f);  // TOCTOU!
            fis.close();
        }
    }

    // 패턴 2: canRead() 검사 후 FileInputStream — TOCTOU
    public void processFile(String path) throws IOException {
        File target = new File(path);

        // [Check] 읽기 권한 검사
        if (target.canRead()) {
            // [Use] 다른 스레드가 권한을 변경하거나 파일을 교체할 수 있음
            FileInputStream fis = new FileInputStream(target);  // TOCTOU!
            fis.close();
        }
    }

    // 패턴 3: exists() 검사 후 delete() — TOCTOU
    public void deleteFile(File f) {
        // [Check] 파일 존재 검사
        if (f.exists()) {
            // [Use] 심볼릭 링크로 교체 후 삭제 유도 가능
            f.delete();  // TOCTOU!
        }
    }
}
