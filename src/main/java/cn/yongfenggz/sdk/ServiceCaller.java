package cn.yongfenggz.sdk;

import com.alibaba.fastjson.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ServiceCaller {

    /**
     * 获取access_token
     *
     * @param baseUrl   请求URL（内部提供）
     * @param clientId  用户ID（内部提供）
     * @param secretKey 密钥（内部提供）
     * @return 			token信息
     * @throws Exception 异常
     */
    public static String getAccessToken(String baseUrl, String clientId, String secretKey) throws Exception {
        Map<String, Object> paramMap = new HashMap<String, Object>();
        long reuqestTimeMs = System.currentTimeMillis();
        paramMap.put("client_id", clientId);
        paramMap.put("request_time_ms", reuqestTimeMs);
        paramMap.put("sign", sha256(secretKey + clientId + reuqestTimeMs));
        String param = JSONObject.toJSON(paramMap).toString();
        String url = baseUrl + "/auth/token";
        return post(url, param, 3000, 3000);
    }

    /**
     * 同步提交请求
     *
     * @param baseUrl          请求URL（内部提供）
     * @param clientId         用户ID（内部提供）
     * @param appCode          业务代码（内部提供）
     * @param apiVersion       api版本号（内部提供）
     * @param secretKey        密钥（内部提供）
     * @param accessToken      Token（调用者获取）
     * @param requestId        调用方的请求ID（调用者提供）
     * @param businessParam    业务参数（调用者提供）
     * @param connectTimeoutMs 连接超时（调用者按需要设置）
     * @param readTimeoutMs    读超时（调用者按需要设置）
     * @return 返回值
     * @throws Exception 异常
     */
    public static String syncRequest(String baseUrl, String clientId, String appCode, String apiVersion,
                                     String secretKey, String accessToken, String requestId, Object businessParam, int connectTimeoutMs,
                                     int readTimeoutMs) throws Exception {
        String param = generateParam(clientId, appCode, apiVersion, secretKey, accessToken, requestId, null,
                businessParam);
        String url = baseUrl + "/" + apiVersion + "/prd/check/syncRequest";
        return post(url, param, connectTimeoutMs, readTimeoutMs);
    }

    /**
     * 异步提交请求
     *
     * @param baseUrl          请求URL（内部提供）
     * @param clientId         用户ID（内部提供）
     * @param appCode          业务代码（内部提供）
     * @param apiVersion       api版本号（内部提供）
     * @param secretKey        密钥（内部提供）
     * @param accessToken      Token（调用者获取）
     * @param requestId        调用方的请求ID（调用者提供）
     * @param businessParam    业务参数（调用者提供）
     * @param connectTimeoutMs 连接超时（调用者按需要设置）
     * @param readTimeoutMs    读超时（调用者按需要设置）
     * @return 返回值
     * @throws Exception 异常
     */
    public static String asyncRequest(String baseUrl, String clientId, String appCode, String apiVersion,
                                      String secretKey, String accessToken, String requestId, Object businessParam, int connectTimeoutMs,
                                      int readTimeoutMs) throws Exception {
        String param = generateParam(clientId, appCode, apiVersion, secretKey, accessToken, requestId, null,
                businessParam);
        String url = baseUrl + "/" + apiVersion + "/prd/check/asyncRequest";
        return post(url, param, connectTimeoutMs, readTimeoutMs);
    }

    /**
     * 获取结果
     *
     * @param baseUrl          请求URL（内部提供）
     * @param clientId         用户ID（内部提供）
     * @param appCode          业务代码（内部提供）
     * @param apiVersion       api版本号（内部提供）
     * @param secretKey        密钥（内部提供）
     * @param accessToken      Token（调用者获取）
     * @param transactionId    交易ID（从asyncRequest接口获取）
     * @param connectTimeoutMs 连接超时（调用者按需要设置）
     * @param readTimeoutMs    读超时（调用者按需要设置）
     * @return 返回值
     * @throws Exception 异常
     */
    public static String getResult(String baseUrl, String clientId, String appCode, String apiVersion, String secretKey,
                                   String accessToken, String transactionId, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        String param = generateParam(clientId, appCode, apiVersion, secretKey, accessToken, null, transactionId, null);
        String url = baseUrl + "/" + apiVersion + "/prd/check/getAsyncResult";
        return post(url, param, connectTimeoutMs, readTimeoutMs);
    }

    private static String generateParam(String clientId, String appCode, String apiVersion, String secretKey,
                                        String accessToken, String requestId, String transactionId, Object businessParam) {
        Base64.Encoder encoder = Base64.getEncoder();
        Map<String, Object> apiParam = new HashMap<String, Object>();
        apiParam.put("api_version", apiVersion);
        apiParam.put("client_id", clientId);
        apiParam.put("app_code", appCode);
        apiParam.put("source", "API");
        apiParam.put("transaction_id", transactionId);
        apiParam.put("request_id", requestId);
        byte[] bytes = JSONObject.toJSON(businessParam).toString().getBytes(StandardCharsets.UTF_8);
        String encodedParam = encoder.encodeToString(bytes);
        apiParam.put("param", encodedParam);
        apiParam.put("access_token", accessToken);
        long requestTimeMs = System.currentTimeMillis();
        apiParam.put("request_time_ms", requestTimeMs);
        apiParam.put("sign",
                sha256(secretKey + clientId + appCode + requestId + accessToken + requestTimeMs + encodedParam));
        return JSONObject.toJSON(apiParam).toString();
    }

    private static String post(String url, String param, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        String responseStr = null;
        SSLContext sslcontext = SSLContexts.custom().build();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new String[]{"TLSv1.2"}, null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(connectTimeoutMs)
                .setSocketTimeout(readTimeoutMs).build();
        HttpClientBuilder builder = HttpClients.custom();
        builder.setSSLSocketFactory(sslsf);
        builder.setDefaultRequestConfig(requestConfig);
        CloseableHttpClient httpclient = builder.build();
        try {
            HttpPost httpPost = new HttpPost(url);
            Charset charset = Charset.forName("UTF-8");
            StringEntity entity = new StringEntity(param, charset);
            entity.setContentEncoding(charset.displayName());
            entity.setContentType("application/json");
            httpPost.setEntity(entity);

            CloseableHttpResponse response = httpclient.execute(httpPost);
            try {
                HttpEntity entity2 = response.getEntity();
                responseStr = EntityUtils.toString(entity2, "UTF-8");
                EntityUtils.consume(entity2);
            } finally {
                response.close();
            }
        } finally {
            httpclient.close();
        }
        return responseStr;
    }

    /**
     * 利用java原生的类实现SHA256加密
     *
     * @param str 加密后的报文
     * @return
     */
    private static String sha256(String str) {
        MessageDigest messageDigest;
        String encodestr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodestr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodestr;
    }

    /**
     * 将byte转为16进制
     *
     * @param bytes
     * @return
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i = 0; i < bytes.length; i++) {
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length() == 1) {
                // 1得到一位的进行补0操作
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }
}
