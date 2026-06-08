package io.oscine.acmecloud;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

public class LoginActivity extends AppCompatActivity {

    private EditText etUser, etPass;
    private TextView tvResult;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_login);

        etUser = findViewById(R.id.etUser);
        etPass = findViewById(R.id.etPass);
        tvResult = findViewById(R.id.tvResult);
        Button btn = findViewById(R.id.btnLogin);
        Button btnWeb = findViewById(R.id.btnWeb);

        btn.setOnClickListener(v -> doLogin());

        // 打开内嵌 WebView（漏洞 M1 演示入口）
        btnWeb.setOnClickListener(v -> {
            Intent i = new Intent(this, WebViewActivity.class);
            i.putExtra("url", Config.BASE_URL + "/login");
            startActivity(i);
        });
    }

    private void doLogin() {
        final String user = etUser.getText().toString();
        final String pass = etPass.getText().toString();

        new AsyncTask<Void, Void, String>() {
            @Override protected String doInBackground(Void... v) {
                try {
                    JSONObject body = new JSONObject();
                    body.put("name", user);
                    body.put("password", pass);
                    return ApiClient.post("/api/login", body.toString());
                } catch (Exception e) {
                    return null;
                }
            }
            @Override protected void onPostExecute(String resp) {
                if (resp == null) {
                    tvResult.setText("请求失败");
                    return;
                }
                try {
                    JSONObject j = new JSONObject(resp);
                    if (j.optBoolean("ok")) {
                        String token = j.optString("token");
                        // M5：明文存储凭证
                        Storage.saveCredentials(LoginActivity.this, user, pass, token);
                        // M7：登录成功把 token 打日志
                        Log.d("AcmeCloudApi", "login success token=" + token);
                        Intent i = new Intent(LoginActivity.this, DashboardActivity.class);
                        startActivity(i);
                        finish();
                    } else {
                        tvResult.setText("登录失败: " + j.optString("error"));
                    }
                } catch (Exception e) {
                    tvResult.setText("响应解析失败: " + resp);
                }
            }
        }.execute();
    }
}
