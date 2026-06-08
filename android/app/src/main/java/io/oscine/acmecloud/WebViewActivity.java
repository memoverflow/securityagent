package io.oscine.acmecloud;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

/**
 * 漏洞 M1：不安全的 WebView
 *   - setJavaScriptEnabled(true)
 *   - addJavascriptInterface 暴露原生对象给页面 JS（API < 17 无 @JavascriptInterface 限制；
 *     这里即使加了注解，暴露的方法本身也提供了读 token / 任意拉起的能力）
 *   - loadUrl 接受外部 Intent 传入的任意 url（配合 M6 导出组件可被外部 App 控制）
 *   - 允许 file:// 与混合内容
 */
public class WebViewActivity extends AppCompatActivity {

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView wv = new WebView(this);
        setContentView(wv);

        wv.getSettings().setJavaScriptEnabled(true);
        wv.getSettings().setAllowFileAccess(true);
        wv.getSettings().setAllowFileAccessFromFileURLs(true);
        wv.getSettings().setAllowUniversalAccessFromFileURLs(true); // 危险：file:// 可读任意源
        wv.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        // 暴露原生桥：页面内任意 JS 都能调用 AndroidBridge.*
        wv.addJavascriptInterface(new NativeBridge(this), "AndroidBridge");

        wv.setWebViewClient(new WebViewClient()); // 不做 URL 白名单，任意跳转都在 WebView 内加载

        // 漏洞：直接信任 Intent 传入的 url（导出组件 M6 + 此处构成完整链）
        String url = getIntent().getStringExtra("url");
        if (url == null && getIntent().getData() != null) {
            url = getIntent().getData().getQueryParameter("target");
        }
        if (url == null) url = Config.BASE_URL;
        wv.loadUrl(url);
    }

    /** 暴露给 WebView JS 的原生桥 —— 任意页面 JS 可调用 */
    public static class NativeBridge {
        private final Context ctx;
        NativeBridge(Context c) { this.ctx = c; }

        // 返回本地明文存储的登录 token —— 恶意/被注入页面可窃取
        @JavascriptInterface
        public String getToken() {
            return Storage.getToken(ctx);
        }

        // 返回硬编码密钥
        @JavascriptInterface
        public String getSigningKey() {
            return Config.API_SIGNING_KEY;
        }

        // 弹原生 toast（演示桥可用）
        @JavascriptInterface
        public void toast(String msg) {
            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show();
        }
    }
}
