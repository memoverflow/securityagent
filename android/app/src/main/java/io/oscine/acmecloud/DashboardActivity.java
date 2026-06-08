package io.oscine.acmecloud;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * 登录后页面。演示移动端如何消费有漏洞的后端 API：
 *   - 用本地明文 token 调 /api/me
 *   - 调用缺角色校验的 /api/admin/users（垂直越权 #9）
 */
public class DashboardActivity extends AppCompatActivity {

    private TextView tv;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_dashboard);
        tv = findViewById(R.id.tvDash);
        Button btnMe = findViewById(R.id.btnMe);
        Button btnAdmin = findViewById(R.id.btnAdmin);

        String user = Storage.getUsername(this);
        tv.setText("已登录: " + user);

        btnMe.setOnClickListener(v -> call("/api/me"));
        btnAdmin.setOnClickListener(v -> call("/api/admin/users"));
    }

    private void call(final String path) {
        new AsyncTask<Void, Void, String>() {
            @Override protected String doInBackground(Void... v) {
                String token = Storage.getToken(DashboardActivity.this);
                return ApiClient.get(path, token);
            }
            @Override protected void onPostExecute(String resp) {
                tv.setText(path + "\n\n" + resp);
            }
        }.execute();
    }
}
