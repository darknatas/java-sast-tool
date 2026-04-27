package com.example.safe;

import java.io.IOException;
import java.nio.file.*;

/**
 * [안전 코드 샘플] 경쟁조건 방지 (IV-3.1, CWE-367)
 *
 * exists() 검사 없이 직접 연산을 시도하고 예외로 실패를 처리.
 * java.nio.file.Files API는 검사와 사용을 단일 시스템 콜로 처리.
 */
public class TOCTOU_AtomicFileOp {

    // 안전: 직접 열기 시도 — NoSuchFileException으로 '없음' 처리
    public void readUserFile(String fileName) {
        Path filePath = Path.of("/app/data/", fileName);
        try (var reader = Files.newBufferedReader(filePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 처리
            }
        } catch (NoSuchFileException e) {
            // 파일 없음 — 정상 처리
        } catch (IOException e) {
            // 처리
        }
    }

    // 안전: 직접 삭제 — NoSuchFileException으로 '없음' 처리
    public void deleteFile(Path filePath) throws IOException {
        Files.deleteIfExists(filePath);
    }

    // 안전: 원자적 파일 생성 — 이미 존재하면 FileAlreadyExistsException
    public void createFile(Path filePath) throws IOException {
        try {
            Files.newOutputStream(filePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).close();
        } catch (FileAlreadyExistsException e) {
            // 이미 존재함 — 처리
        }
    }
}
