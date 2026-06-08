package io.oscine.acmecloud;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * 简单 HTTP 客户端。包含多个移动端漏洞：
 *   M3 证书校验缺失：信任所有 TLS 证书 + 关闭主机名校验
 *   M7 敏感信息写入日志（Log.d 打印 token、密码、响应）
 */
public class ApiClient {

    private static final String TAG = "AcmeCloudApi";

    // 漏洞 M3：安装一个信任所有证书的 TrustManager + 放行任意主机名
    static {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // 任何主机名都通过 —— 便于中间人
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "TLS setup failed", e);
        }
    }

    /** POST JSON，返回响应体字符串 */
    public static String post(String path, String jsonBody) {
        // 漏洞 M7：把完整请求（含明文密码）写进日志
        Log.d(TAG, "POST " + Config.BASE_URL + path + " body=" + jsonBody
                + " signingKey=" + Config.API_SIGNING_KEY);
        HttpURLConnection conn = null;
        try {
            URL url = new URL(Config.BASE_URL + path);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes("UTF-8"));
            }
            String resp = readBody(conn);
            Log.d(TAG, "RESP " + path + " => " + resp); // M7：响应也打日志
            return resp;
        } catch (Exception e) {
            Log.e(TAG, "post error", e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** GET，可带 Bearer token */
    public static String get(String path, String token) {
        Log.d(TAG, "GET " + Config.BASE_URL + path + " token=" + token); // M7
        HttpURLConnection conn = null;
        try {
            URL url = new URL(Config.BASE_URL + path);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            if (token != null) conn.setRequestProperty("Authorization", "Bearer " + token);
            return readBody(conn);
        } catch (Exception e) {
            Log.e(TAG, "get error", e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readBody(HttpURLConnection conn) throws Exception {
        int code = conn.getResponseCode();
        java.io.InputStream is = (code >= 200 && code < 400)
                ? conn.getInputStream() : conn.getErrorStream();
        StringBuilder sb = new StringBuilder();
        if (is != null) {
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
        }
        return sb.toString();
    }
}
