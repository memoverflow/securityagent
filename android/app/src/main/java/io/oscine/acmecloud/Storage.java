package io.oscine.acmecloud;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * 漏洞 M5：敏感数据明文存储
 * token、用户名、密码以明文写入 SharedPreferences（/data/data/<pkg>/shared_prefs/auth.xml），
 * root 或 adb backup 可直接读出。
 */
public class Storage {
    private static final String PREF = "auth";

    public static void saveCredentials(Context ctx, String user, String pass, String token) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        sp.edit()
            .putString("username", user)
            .putString("password", pass)   // 明文密码
            .putString("token", token)      // 明文 token
            .apply();
    }

    public static String getToken(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString("token", null);
    }

    public static String getUsername(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString("username", null);
    }
}
