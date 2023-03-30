package com.example.httpstest;


import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import android.annotation.SuppressLint;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Objects;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    public static final String TAG = "HttpTest";
    private Button btn_http_connect;
    private Button btn_https_connect_without_ca;
    private Button btn_https_connect_with_system_ca;
    private Button btn_ssl_pinning_with_key;
    private Button btn_ssl_pinning_with_ca;
    private Button btn_https_bothway;
    private Button btn_webview_ssl_without_ca;
    private Button btn_webview_ssl_with_system_ca;
    private Button btn_webview_ssl_pinning;
    private SwitchCompat sc_check_proxy;
    private TextView tv_show;
    private WebView wv_show;

    OkHttpClient client = new OkHttpClient();

    public static SSLContext sslContext = null;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btn_http_connect = (Button) findViewById(R.id.btn_http_connect);
        btn_https_connect_without_ca = (Button) findViewById(R.id.btn_https_connect_without_ca);
        btn_https_connect_with_system_ca = (Button) findViewById(R.id.btn_https_connect_with_system_ca);
        btn_ssl_pinning_with_key = (Button) findViewById(R.id.btn_ssl_pinning_with_key);
        btn_ssl_pinning_with_ca = (Button) findViewById(R.id.btn_ssl_pinning_with_ca);
        btn_https_bothway = (Button) findViewById(R.id.btn_https_bothway);
        btn_webview_ssl_without_ca = (Button) findViewById(R.id.btn_webview_ssl_without_ca);
        btn_webview_ssl_with_system_ca = (Button) findViewById(R.id.btn_webview_ssl_with_system_ca);
        btn_webview_ssl_pinning = (Button) findViewById(R.id.btn_webview_ssl_pinning);
        sc_check_proxy = (SwitchCompat) findViewById(R.id.sc_check_proxy);
        tv_show = (TextView) findViewById(R.id.tv_show);
        wv_show = (WebView) findViewById(R.id.wv_show);

        // 注册Handler处理从thread中返回的url请求结果
        @SuppressLint("HandlerLeak") final Handler mHandler = new Handler() {
            public void handleMessage(Message msg) {
                // 处理消息
                super.handleMessage(msg);
                switch (msg.what) {
                    case 1:
                        tv_show.setText((CharSequence) msg.obj);
                        break;
                }
            }
        };


        /*
         * HTTP CONNECT(HTTP直连)
         *
         * http协议
         * */
        btn_http_connect.setOnClickListener(view -> new Thread(() -> {
            String btn_text = String.format("<%s>", ((Button) view).getText());
            String url = "http://www.httpbin.org/get";

            Message message = new Message();
            message.what = 1;

            OkHttpClient mClient = client.newBuilder().build();
            Request request = new Request.Builder()
                    .url(url)
                    .build();
            try (Response response = mClient.newCall(request).execute()) {
                message.obj = String.format("%s Access \"%s\" success", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, url, response.code()));
            } catch (IOException e) {
                message.obj = String.format("%s Access \"%s\" failed", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, url));
                e.printStackTrace();
            }
            mHandler.sendMessage(message);

        }).start());



        /*
         * HTTPS CONNECT(忽略证书校验)
         *
         * https协议
         * 忽略证书验证
         * */
        btn_https_connect_without_ca.setOnClickListener(view -> new Thread(() -> {
            String btn_text = String.format("<%s>", ((Button) view).getText());
            String url = "https://www.baidu.com/s?wd=trustAllCerts";

            Message message = new Message();
            message.what = 1;

            OkHttpClient mClient = client.newBuilder().sslSocketFactory(
                            HttpsTrustAllCerts.createSSLSocketFactory(),
                            new HttpsTrustAllCerts())
                    .hostnameVerifier(new HttpsTrustAllCerts.TrustAllHostnameVerifier()).build();
            Request request = new Request.Builder()
                    .url(url)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
                    .build();
            try (Response response = mClient.newCall(request).execute()) {
                message.obj = String.format("%s Access \"%s\" success", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, url, response.code()));
            } catch (IOException e) {
                message.obj = String.format("%s Access \"%s\" failed", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, url));
                e.printStackTrace();
            }
            mHandler.sendMessage(message);

        }).start());


        /*
         * HTTPS CONNECT(系统证书校验)
         *
         * https协议
         * 默认证书链校验，只信任系统CA(根证书)
         *
         * tips: OKHTTP默认的https请求使用系统CA验证服务端证书（Android7.0以下还信任用户证书，Android7.0开始默认只信任系统证书）
         * */
        btn_https_connect_with_system_ca.setOnClickListener(view -> new Thread(() -> {
            String btn_text = String.format("<%s>", ((Button) view).getText());
            String url = "https://www.baidu.com/s?wd=defaultCerts";

            Message message = new Message();
            message.what = 1;

            Request request = new Request.Builder()
                    .url(url)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
                    .build();
            try (Response response = client.newCall(request).execute()) {
                message.obj = String.format("%s Access \"%s\" success", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, url, response.code()));
            } catch (IOException e) {
                message.obj = String.format("%s Access \"%s\" failed", btn_text, url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, url));
                e.printStackTrace();
            }
            mHandler.sendMessage(message);

        }).start());


        /*
         * SSL PINNING(代码校验)
         *
         * https协议 SSL Pinning
         * 证书公钥绑定：验证证书公钥 baidu.com 使用CertificatePinner
         * 证书文件绑定：验证证书文件 bing.com  使用SSLSocketFactory
         * */
        btn_ssl_pinning_with_key.setOnClickListener(view -> new Thread(() -> {
            String btn_text = String.format("<%s>", ((Button) view).getText());
            String baidu_url = "https://www.baidu.com/s?wd=SSLPinningCode";
            String bing_url = "https://cn.bing.com/search?q=SSLPinningCAfile";

            Message message = new Message();
            message.what = 1;

            // 证书公钥绑定
            final String CA_DOMAIN = "www.baidu.com";
            //获取目标公钥: openssl s_client -connect www.baidu.com:443 -servername www.baidu.com | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
            final String CA_PUBLIC_KEY = String.format("sha256/%s", "Zhv4cvwdHmEmE0edWEcIdmLfwsqxrrOmp+vbngwNnrU=");
            //只校验公钥
            CertificatePinner pinner = new CertificatePinner.Builder()
                    .add(CA_DOMAIN, CA_PUBLIC_KEY)
                    .build();
            OkHttpClient pClient1 = client.newBuilder().certificatePinner(pinner).build();
            Request request1 = new Request.Builder()
                    .url(baidu_url)
                    .build();
            try (Response response1 = pClient1.newCall(request1).execute()) {
                message.obj = String.format("%s Access \"%s\" success", btn_text, baidu_url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, baidu_url, response1.code()));
            } catch (IOException e) {
                message.obj = String.format("%s Access \"%s\" failed", btn_text, baidu_url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, baidu_url));
                e.printStackTrace();
            }

            message.obj += "\n";

            // 证书文件绑定
            try {
                // 获取证书输入流
                // 获取证书 openssl s_client -connect bing.com:443 -servername bing.com | openssl x509 -out bing.pem
                InputStream openRawResource = getApplicationContext().getResources().openRawResource(R.raw.bing); //R.raw.bing是bing.com的正确证书，R.raw.so是hostname=bing.com的so.com的证书，可视为用作测试的虚假bing.com证书
                Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(openRawResource);
                // 创建 Keystore 包含我们的证书
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setCertificateEntry("ca", ca);
                // 创建一个 TrustManager 仅把 Keystore 中的证书 作为信任的锚点
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // 建议不要使用自己实现的X509TrustManager，而是使用默认的X509TrustManager
                trustManagerFactory.init(keyStore);
                // 用 TrustManager 初始化一个 SSLContext
                sslContext = SSLContext.getInstance("TLS");  //定义：public static SSLContext sslContext = null;
                sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

                OkHttpClient pClient2 = client.newBuilder().sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagerFactory.getTrustManagers()[0]).build();
                Request request2 = new Request.Builder()
                        .url(bing_url)
                        .build();
                try (Response response2 = pClient2.newCall(request2).execute()) {
                    message.obj += String.format("%s Access \"%s\" success", btn_text, bing_url);
                    Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, bing_url, response2.code()));
                } catch (IOException e) {
                    message.obj += String.format("%s Access \"%s\" failed", btn_text, bing_url);
                    Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, bing_url));
                    e.printStackTrace();
                }

            } catch (KeyStoreException | CertificateException | IOException |
                     NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }
            mHandler.sendMessage(message);

        }).start());



        /*
         * SSL PINNING(配置文件)
         *
         * https协议 SSL PINNING
         * 证书绑定验证 配置在 @xml/network_security_config 中
         * sogou.com 使用 sogou.pem 验证证书
         * so.com 使用 sha256 key 验证
         * */
        btn_ssl_pinning_with_ca.setOnClickListener(view -> new Thread(() -> {
            String btn_text = String.format("<%s>", ((Button) view).getText());
            String sogou_url = "https://www.sogou.com/web?query=SSLPinningXML";
            String zhihu_url = "https://www.zhihu.com/";

            Message message = new Message();
            message.what = 1;

            OkHttpClient pClient = client.newBuilder().build();

            Request request1 = new Request.Builder()
                    .url(sogou_url)
                    .build();
            try (Response response1 = pClient.newCall(request1).execute()) {
                message.obj = String.format("%s Access \"%s\" success", btn_text, sogou_url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, sogou_url, response1.code()));
            } catch (IOException e) {
                message.obj = String.format("%s Access \"%s\" failed", btn_text, sogou_url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, sogou_url));
                e.printStackTrace();
            }

            message.obj += "\n";

            Request request2 = new Request.Builder()
                    .url(zhihu_url)
                    .build();
            try (Response response2 = pClient.newCall(request2).execute()) {
                message.obj += String.format("%s Access \"%s\" success", btn_text, zhihu_url);
                Log.d(TAG, String.format("%s Access \"%s\" success return code: %s", btn_text, zhihu_url, response2.code()));
            } catch (IOException e) {
                message.obj += String.format("%s Access \"%s\" failed", btn_text, zhihu_url);
                Log.d(TAG, String.format("%s Access \"%s\" failed", btn_text, zhihu_url));
                e.printStackTrace();
            }
            mHandler.sendMessage(message);

        }).start());


        /*
         * HTTPS 双向校验
         *
         * 双向校验
         * 因该测试是自建服务器并自签名，所以需要先在res/xml/network_security_config中配置信任服务端证书
         * */
        btn_https_bothway.setOnClickListener(view -> new Thread(() -> {
            String url = "https://www.test.com/?q=BothWayVerify";

            Message message = new Message();
            message.what = 1;

            X509TrustManager trustManager = null;
            try {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

                trustManagerFactory.init((KeyStore) null);
                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                    throw new IllegalStateException("Unexpected default trust managers:" + Arrays.toString(trustManagers));
                }
                trustManager = (X509TrustManager) trustManagers[0];
            } catch (Exception e) {
                e.printStackTrace();
            }
            OkHttpClient mClient = client.newBuilder().sslSocketFactory(
                    Objects.requireNonNull(ClientSSLSocketFactory.getSocketFactory(getApplicationContext())),
                    Objects.requireNonNull(trustManager)
            ).hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
                    return hv.verify("www.test.com", session);
                }
            }).build();

            Request request = new Request.Builder()
                    .url(url)
                    .build();
            try (Response response = mClient.newCall(request).execute()) {
                assert response.body() != null;
                String result = response.body().string();
                long length = response.body().contentLength();
                message.obj = String.format("请求成功: %s", result);
                Log.d(TAG, String.format("请求成功: %s, 响应体长度: %s", result, length));
                mHandler.sendMessage(message);
            } catch (IOException e) {
                message.obj = e.getLocalizedMessage();
                mHandler.sendMessage(message);
                e.printStackTrace();
            }

        }).start());


        /*
         * WEBVIEW SSL(忽略证书校验)
         *
         * https协议
         * WebView 不进行证书校验
         * */
        btn_webview_ssl_without_ca.setOnClickListener(view -> {
            CustomWebViewClient mWebViewClient = new CustomWebViewClient();
            mWebViewClient.setCheckflag("trustAllCerts");
            wv_show.setWebViewClient(mWebViewClient);
            wv_show.loadUrl("https://www.baidu.com/s?wd=WebView_without_CAcheck");
        });

        /*
         * WEBVIEW SSL(系统证书校验)
         *
         * https协议
         * WebView 使用系统证书校验
         * */
        btn_webview_ssl_with_system_ca.setOnClickListener(view -> {
            CustomWebViewClient mWebViewClient = new CustomWebViewClient();
            mWebViewClient.setCheckflag("checkCerts");
            wv_show.setWebViewClient(mWebViewClient);
            wv_show.loadUrl("https://www.qq.com/search.htm?query=WebView_with_SystemCAcheck");
        });


        /*
         * WEBVIEW SSL(SSL PINNING)
         *
         * https协议 SSL PINNING WebView
         * 通过network_security_config.xml中定义的证书和密钥进行绑定
         * */
        btn_webview_ssl_pinning.setOnClickListener(view -> {
            CustomWebViewClient mWebViewClient = new CustomWebViewClient();
            mWebViewClient.setCheckflag("checkCerts");
            wv_show.setWebViewClient(mWebViewClient);
            // wv_show.loadUrl("https://www.sogou.com/web?query=WebView_SSLPinningXML"); // 证书文件校验
            wv_show.loadUrl("https://www.zhihu.com/"); // 证书公钥校验
        });


        /*
         * 检测代理
         *
         * 目前仅限OkHttp发出的请求
         * */
        sc_check_proxy.setOnCheckedChangeListener((compoundButton, b) -> {
            if (b) {
                client = new OkHttpClient().newBuilder().proxy(Proxy.NO_PROXY).build();
            } else {
                client = new OkHttpClient();
            }
        });

    }

    private class CustomWebViewClient extends WebViewClient {
        private String checkflag = "checkCerts"; // 是否忽略证书校验

        public void setCheckflag(String checkflag) {
            this.checkflag = checkflag;
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            if ("trustAllCerts".equals(checkflag)) {
                handler.proceed();
            } else {
                handler.cancel();
                Toast.makeText(MainActivity.this, "证书异常，停止访问", Toast.LENGTH_SHORT).show();
            }
        }
    }

}