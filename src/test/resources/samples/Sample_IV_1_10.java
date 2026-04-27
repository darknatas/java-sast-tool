package com.example.sample;
import javax.servlet.http.HttpServletRequest;
import javax.naming.*;
import javax.naming.directory.*;
public class Sample_IV_1_10 {
    void vuln(HttpServletRequest req, DirContext ctx) throws Exception {
        String user = req.getParameter("user");
        ctx.search("dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
    }
}
