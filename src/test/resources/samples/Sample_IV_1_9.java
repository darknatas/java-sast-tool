package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.*;
public class Sample_IV_1_9 {
    void vuln(HttpServletRequest req, XPath xpath) throws Exception {
        String user = req.getParameter("user");
        xpath.evaluate("/users[@name='" + user + "']", (Object) null);
    }
}
