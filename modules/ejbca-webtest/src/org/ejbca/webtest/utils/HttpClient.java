package org.ejbca.webtest.utils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;

public class HttpClient {
    private final String USER_AGENT = "Mozilla/5.0";
    private static String url;
    private static String parameters;

    public HttpClient(String url, String parameters) {
        HttpClient.url = url;
        HttpClient.parameters = parameters;
    }

    public int sendJsonPost() {
        try {
            org.apache.http.client.HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost request = new HttpPost(HttpClient.url);
            request.setHeader("Accept", "application/json");
            request.setHeader("Content-type", "application/json");

            StringEntity entity = new StringEntity(parameters, ContentType.APPLICATION_FORM_URLENCODED);
            request.setEntity(entity);

            HttpResponse response = httpClient.execute(request);

            System.out.println("Return Code:  " + response.getStatusLine().getStatusCode());
            System.out.println("Return Message:  " + response.getStatusLine().getReasonPhrase());

            return response.getStatusLine().getStatusCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return 0;
    }

    /**
     * Send an HTTP post command optionally with parameters
     *
     * @return
     * @throws Exception
     */
    public String sendPost() {


        StringBuffer response = new StringBuffer();
        try {
            URL obj =new URL(url);
            URLConnection conn=obj.openConnection();

            conn.setUseCaches(true);
            conn.setDoOutput(true);
            if (conn instanceof HttpsURLConnection) {
                HttpsURLConnection secureConn=(HttpsURLConnection)conn;
                secureConn.setSSLSocketFactory(getSSL().getSocketFactory());
                //secureConn.setHostnameVerifier(HOSTNAME_VERIFIER);
            }



        /*
            //Open a connection

            SSLContext sc = getSSL();
            System.out.println("sc loc:  " + sc.getProtocol());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            System.out.println("https:  " + HttpsURLConnection.getDefaultAllowUserInteraction());
            URL obj = new URL(this.url);

            System.out.println("obj:  " + obj.getHost());
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            System.out.println("con:  " + con.getContentType());

            con.setSSLSocketFactory(sc.getSocketFactory());
            System.out.println("con:  " + con.getURL());

            //Add request header
            con.setRequestMethod("POST");
            //con.setRequestProperty("Accept", "application/json");
            //con.setRequestProperty("Content-Type","application/json");
            con.setRequestProperty("User-Agent", USER_AGENT);
            con.setRequestProperty("Accept Language", "en-US,en;q=0.5");

            /*



            //Add request header
            con.setRequestMethod("POST");
            con.setRequestProperty("Accept", "application/json");
            con.setRequestProperty("Content-Type","application/json");
            con.setRequestProperty("User-Agent", USER_AGENT);
            con.setRequestProperty("Accept Language", "en-US,en;q=0.5");

            //Send post request based on the number of occurrences
            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());

            wr.writeBytes(this.parameters);
            wr.flush();
            wr.close();

            int responseCode = con.getResponseCode();
            String responseMessage = con.getResponseMessage();

            //Write to console
            System.out.println("\nSending 'POST' request to URL : " + this.url);
            System.out.println("Post parameters : " + this.parameters);
            System.out.println("Response Code : " + responseCode);
            System.out.println("Response Message:  " + responseMessage);

            System.out.println("5");

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            System.out.println("6");

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }

            in.close();
            System.out.println("7");
        */
        } catch (Exception e) {
            System.out.println("error:  " + e.getLocalizedMessage());
            e.printStackTrace();
        }


        //Return results
        return ( response.toString() );
    }

    public String sendGet() throws IOException {

        //Open a connection
        HttpsURLConnection.setDefaultSSLSocketFactory(getSSL().getSocketFactory());
        URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

        // optional default is GET
        con.setRequestMethod("GET");

        //add request header
        con.setRequestProperty("User-Agent", USER_AGENT);

        int responseCode = con.getResponseCode();
        System.out.println("\nSending 'GET' request to URL : " + url);
        System.out.println("Response Code : " + responseCode);

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
    }

    /**
     * Generate the p12 and trustcore for the HttpsURLConnection
     *
     * @return
     */
    private SSLContext getSSL() {
        SSLContext sslContext = null;
        try {
            KeyStore clientStore = KeyStore.getInstance("PKCS12");
            clientStore.load(new FileInputStream("./p12/superadmin.p12"), "ejbca".toCharArray());
            System.out.println("client store:  " + clientStore.size());
            System.out.println("client store loc:  " + System.getProperty("user.dir") + "/p12/superadmin.p12");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientStore, "ejbca".toCharArray());
            KeyManager[] kms = kmf.getKeyManagers();
            System.out.println("Key Manager store:  " + kms.length);

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("./p12/truststore.jks"), "changeit".toCharArray());
            System.out.println("truststore store:  " + trustStore.size());
            System.out.println("truststore loc:  " + System.getProperty("user.dir") + "/p12/truststore.jks");

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            TrustManager[] tms = tmf.getTrustManagers();
            System.out.println("trustmanager store:  " + tms.length);


            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kms, tms, new SecureRandom());
            //sslContext.init(kmf.getKeyManagers(), null, null);
            System.out.println("here we are:  " + sslContext.getProtocol());


        } catch (KeyStoreException | KeyManagementException | UnrecoverableKeyException | CertificateException |
                NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return sslContext;
    }

}
