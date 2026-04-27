package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import java.sql.*;

/**
 * [취약 코드 샘플] SQL 삽입 (IV-1.1, CWE-89)
 *
 * 외부 입력값을 문자열 연결로 SQL 쿼리에 삽입 — SQL 삽입 취약점 존재
 */
public class BoardController {

    public void getBoardList(HttpServletRequest request, Connection con) throws Exception {

        // [Source] 신뢰할 수 없는 외부 입력값
        String gubun = request.getParameter("gubun");

        // [Propagation] 오염된 값이 SQL 문자열로 전파
        String sql = "SELECT * FROM board WHERE b_gubun = '" + gubun + "'";

        Statement stmt = con.createStatement();

        // [Sink] 오염된 sql이 executeQuery에 사용 → SQL 삽입 취약점
        ResultSet rs = stmt.executeQuery(sql);

        while (rs.next()) {
            System.out.println(rs.getString("title"));
        }
    }

    public void getUserById(HttpServletRequest request, Connection con) throws Exception {

        // [Source] 사용자 입력
        String userId = request.getParameter("id");

        // [Propagation] 오염 전파
        String query = "SELECT name, email FROM users WHERE user_id = '" + userId + "'";

        Statement stmt = con.createStatement();

        // [Sink] SQL 삽입 취약점
        ResultSet rs = stmt.executeQuery(query);
    }
}
