package com.example.sample;
import java.io.*;
import javax.servlet.http.HttpServletRequest;
public class Sample_IV_5_5 {
    void vuln(HttpServletRequest req) throws Exception {
        InputStream raw = req.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(raw);
        Object obj = ois.readObject();
    }
}
