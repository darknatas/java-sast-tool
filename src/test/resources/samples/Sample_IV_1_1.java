package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
public class Sample_IV_1_1 {
    void vuln(HttpServletRequest req, Statement stmt) throws Exception {
        String id  = req.getParameter("id");
        String sql = "SELECT * FROM users WHERE id='" + id + "'";
        stmt.executeQuery(sql);
    }
}
