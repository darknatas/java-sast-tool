package com.example.sample;
import javax.xml.xpath.*;
public class Sample_DS_1_2 {
    void vuln(XPath xpath, String user) throws Exception {
        xpath.evaluate("/users[@name='" + user + "']", (Object) null);
    }
}
