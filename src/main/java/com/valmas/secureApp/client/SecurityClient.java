package com.valmas.secureApp.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.NonNull;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;

public class SecurityClient {

    private static final String LOGIN_ENDPOINT = "https://localhost:8085/login";
    public static final String KEYSTORE_PATH = "/home/valmas/work/myWork/secureApp/clientKeystore.p12";
    public static final String KEYSTORE_PASSWORD = "123456";

    private static PrivateKey loadPrivateKey(String keystorePassword, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        final InputStream keystoreFile = new FileInputStream(KEYSTORE_PATH);
        keyStore.load(keystoreFile, keystorePassword.toCharArray());

        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(keystorePassword.toCharArray());

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, protParam);
        return pkEntry.getPrivateKey();
    }

    private static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(message.getBytes());
    }

    public static void main(String[] args) throws Exception {
        final PrivateKey privateKey = loadPrivateKey(KEYSTORE_PASSWORD, "admin");
        final byte[] encryptedPass = encrypt(privateKey, "1234");

        final String base64 = Base64.getEncoder().encodeToString(encryptedPass);
        System.out.println("Enctypted: " + base64);

        AuthenticationRequest req = new AuthenticationRequest("mykey", base64);
        String json = new ObjectMapper().writeValueAsString(req);

        System.setProperty("javax.net.ssl.trustStore", KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword", KEYSTORE_PASSWORD);

        invokeLogin(json);
    }

    private static void invokeLogin(String json) throws IOException {
        URL url = new URL(LOGIN_ENDPOINT);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        OutputStream os = conn.getOutputStream();
        os.write(json.getBytes());
        os.flush();

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed : HTTP error code : "
                    + conn.getResponseCode());
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(
                (conn.getInputStream())));
        String output;
        System.out.println("Output from Server .... \n");
        while ((output = br.readLine()) != null) {
            System.out.println(output);
        }

        String jwt = conn.getHeaderField("Authorization");
        System.out.println("JWT: " + jwt);

        conn.disconnect();
    }

    @Data
    private static class AuthenticationRequest {

        @NonNull
        private String alias;
        @NonNull
        private String signature;
    }

}
