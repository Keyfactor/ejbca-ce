package org.cesecore.azure;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.cesecore.azure.IntuneRestApi.Builder;
import org.junit.Test;

import static org.junit.Assume.assumeNotNull;

/**
 * These are really integration tests.  They will only work 
 * if the secret/keystore are set in system properties defined 
 * below (and it the tenant and application id are as specified 
 * below as well).
 */
public class IntuneRestApiTest {
    @Test
    public void intuneClientWithSecretCanConnect() throws IOException, AzureException {
        assumeNotNull(System.getProperty("CURRENT_INTUNE_SECRET"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String secret = System.getProperty("CURRENT_INTUNE_SECRET");

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientSecret(secret).build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test
    public void intuneClientWithCertificateCanConnect()
            throws IOException, AzureException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        assumeNotNull(System.getProperty("CURRENT_AZURE_KEYSTORE"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String password = System.getProperty("CURRENT_AZURE_KEYSTORE_PASSWORD");
        String keystorePath = System.getProperty("CURRENT_AZURE_KEYSTORE");

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream keystoreFile = new FileInputStream(keystorePath)) {
            keystore.load(keystoreFile, password.toCharArray());
        }
        String alias = keystore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
        PrivateKey key = (PrivateKey) keystore.getKey(alias, password.toCharArray());

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientCertificate(certificate).withClientKey(key).build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test
    public void canSpecifyResourceUrl() throws IOException, AzureException {
        assumeNotNull(System.getProperty("CURRENT_INTUNE_SECRET"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String secret = System.getProperty("CURRENT_INTUNE_SECRET");

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientSecret(secret).withGraphResourceUrl("graph.microsoft.com").withGraphResourceVersion("v1.0").build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test
    public void canSpecifyResourceUrlWithProtocol() throws IOException, AzureException {
        assumeNotNull(System.getProperty("CURRENT_INTUNE_SECRET"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String secret = System.getProperty("CURRENT_INTUNE_SECRET");

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientSecret(secret).withGraphResourceUrl("https://graph.microsoft.com").withGraphResourceVersion("v1.0")
                .build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test(expected = AzureException.class)
    public void badResourseUrlFails() throws IOException, AzureException {
        assumeNotNull(System.getProperty("CURRENT_INTUNE_SECRET"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String secret = System.getProperty("CURRENT_INTUNE_SECRET");

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientSecret(secret).withGraphResourceUrl("https://graph2.microsoft.com").withGraphResourceVersion("v1.0")
                .build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test(expected = AzureException.class)
    public void badIntuneResourseUrlFails() throws IOException, AzureException {
        assumeNotNull(System.getProperty("CURRENT_INTUNE_SECRET"));

        String tenantId = "8375a5cc-74ce-45e8-abc1-00a87441a554";
        String applicationId = "c002d28b-f0de-4f59-82dd-f68df79fbf5b";
        String secret = System.getProperty("CURRENT_INTUNE_SECRET");

        Builder builder = new IntuneRestApi.Builder(tenantId, applicationId, "unittest");
        IntuneRestApi intune = builder.withClientSecret(secret).withIntuneResourceUrl("https://api2.manage.microsoft.com/").build();
        intune.downloadRevocationRequests(50, null);
    }

    @Test
    public void canBuildWithoutProxy() {
        new IntuneRestApi.Builder("test", "test", "test").withClientSecret("test").build();
    }

    @Test
    public void canBuildWithPasswordlessProxy() {
        new IntuneRestApi.Builder("test", "test", "test").withClientSecret("test").withProxyHost("localhost")   .withProxyPort(9000).build();
    }

    @Test
    public void canBuildWithPasswordProxy() {
        new IntuneRestApi.Builder("test", "test", "test").withClientSecret("test").withProxyHost("localhost").withProxyPort(9000)
                .withProxyPassword("test").withProxyUser("test").build();
    }

}
