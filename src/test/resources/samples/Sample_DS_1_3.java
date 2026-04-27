package com.example.sample;
import javax.naming.directory.*;
public class Sample_DS_1_3 {
    void vuln(DirContext ctx, String user) throws Exception {
        ctx.search("dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
    }
}
