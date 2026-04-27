package com.example.sample;
import java.sql.*;
public class Sample_DS_1_1 {
    void vuln(Statement stmt, String id) throws Exception {
        String sql = "SELECT * FROM users WHERE id='" + id + "'";
        stmt.executeQuery(sql);  // DS-1.1: SQL 바인딩 미적용
    }
}
