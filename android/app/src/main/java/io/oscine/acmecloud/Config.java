package io.oscine.acmecloud;

/**
 * 漏洞 M4：硬编码密钥/凭证
 * 反编译 APK 即可提取以下所有敏感常量。
 */
public final class Config {
    // 后端基址（默认走部署好的靶站；模拟器连本机用 http://10.0.2.2:3000）
    public static final String BASE_URL = "https://pentest.oscine.io";

    // 硬编码 API 密钥（与服务端 /api/debug 泄露的 signingKey 对应）
    public static final String API_SIGNING_KEY = "acme-cloud-static-hmac-key-2026";

    // 硬编码后台账号（开发者图省事写死的"运维后门"）
    public static final String ADMIN_USER = "admin";
    public static final String ADMIN_PASS = "sup3r-s3cret";

    // 第三方服务 token（示例）
    public static final String ANALYTICS_TOKEN = "ak_live_4e9c1f7b8d2a6005";

    private Config() {}
}
