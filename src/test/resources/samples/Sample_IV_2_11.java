package com.example.sample;
import javax.net.ssl.*;
import java.security.cert.*;
public class Sample_IV_2_11 {
    void vuln() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {  // IV-2.11: 모든 인증서 신뢰
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
    }
}
