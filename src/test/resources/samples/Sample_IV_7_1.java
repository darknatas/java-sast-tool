package com.example.sample;
import java.net.*;
public class Sample_IV_7_1 {
    boolean isTrustedHost(String host) throws Exception {
        String resolved = InetAddress.getByName(host).getHostName();
        return resolved.endsWith(".trusted.com");  // IV-7.1: DNS 역조회 의존
    }
}
