package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.script.*;
public class Sample_IV_1_2 {
    void vuln(HttpServletRequest req, ScriptEngine engine) throws Exception {
        String code = req.getParameter("code");
        engine.eval(code);
    }
}
