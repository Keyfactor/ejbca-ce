/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.azure;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import com.google.common.base.Preconditions;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import static org.json.simple.JSONObject.writeJSONString;

/**
 * Interface to Microsoft Azure Intune device management service's PKI API.
 * Connects EJBCA SCEP issuance with Intune's database of device certificates.
 */
public class IntuneRestApi {

    /**
     * Note that this Enum has the following license
     *
     * @formatter:off
     * Copyright (c) Microsoft Corporation.
     * All rights reserved.
     *
     * This code is licensed under the MIT License.
     *
     * Permission is hereby granted, free of charge, to any person obtaining a copy
     * of this software and associated documentation files(the "Software"), to deal
     * in the Software without restriction, including without limitation the rights
     * to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
     * copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions :
     *
     * The above copyright notice and this permission notice shall be included in
     * all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
     * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
     * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
     * THE SOFTWARE.
     * @formatter:on
     * CARequestErrorCodes - Error Codes for CA Request Results.
     */
    public enum CARequestErrorCodes {
        // No Errors Occurred
        None("0"),

        // General Non-Retryable Service error
        NonRetryableServiceException("4000"),
        // Data failed to deserialize correctly (non-retryable).
        DataSerializationError("4001"),
        // Data contained invalid parameters (non-retryable).
        ParameterDataInvalidError("4002"),
        // Cryptography error attempting to fulfill request (non-retryable).
        CryptographyError("4003"),
        // Could not locate the requested Certificate (non-retryable).
        CertificateNotFoundError("4004"),
        // Conflict processing request"), Ex. trying to revoke an already revoked certificate (non-retryable)
        ConflictError("4005"),
        // Request  Not Supported (non-retryable).
        NotSupportedError("4006"),
        // Request is larger than what is allowed by the requesting service (non-retryable).
        PayloadTooLargeError("4007"),
        // General Retryable Service error
        RetryableServiceException("4100"),
        // Service Unavailable Exception (retryable).
        ServiceUnavailableException("4101"),
        // Service Too Busy Exception (retryable).
        ServiceTooBusyException("4102"),
        // Authentication Failure Exception (retryable).
        AuthenticationException("4103");

        public final String Value;

        private CARequestErrorCodes(String value) {
            this.Value = value;
        }
    }

    Logger logger = Logger.getLogger(getClass());

    private static final String DEFAULT_GRAPH_VERSION = "v1.0";
    private static final String DEFAULT_GRAPH_URL = "https://graph.microsoft.com";
    private static final String INTUNE_API_VERSION = "5019-05-05";
    private final static String DEFAULT_INTUNE_URL = "https://api.manage.microsoft.com/";

    /**
     * Single revocation request from Inune
     */
    public static class RevocationRequest {
        public String requestContext;
        public String serialNumber;
        public String issuerName;
        public String caConfiguration;

        public RevocationRequest(String requestContext, String serialNumber, String issuerName, String caConfiguration) {
            this.requestContext = requestContext;
            this.serialNumber = serialNumber;
            this.issuerName = issuerName;
            this.caConfiguration = caConfiguration;
        }

        @Override
        public String toString() {
            return "RevocationRequest [requestContext=" + requestContext + ", serialNumber=" + serialNumber + ", issuerName=" + issuerName
                    + ", caConfiguration=" + caConfiguration + "]";
        }
    }

    /**
     * Single revocation result for Intune
     */
    public static class RevocationResult {
        public String requestContext;
        public boolean succeeded;
        public String errorCode;
        public String errorMessage;

        public RevocationResult(String requestContext, boolean succeeded, String errorCode, String errorMessage) {
            this.requestContext = requestContext;
            this.succeeded = succeeded;
            this.errorCode = errorCode;
            this.errorMessage = errorMessage;
        }

        public RevocationResult(String requestContext, boolean succeeded, CARequestErrorCodes errorCode, String errorMessage) {
            this.requestContext = requestContext;
            this.succeeded = succeeded;
            this.errorCode = errorCode.Value;
            this.errorMessage = errorMessage;
        }

        public RevocationResult(String requestContext) {
            this.requestContext = requestContext;
            this.succeeded = true;
            this.errorCode = CARequestErrorCodes.None.Value;
            this.errorMessage = "";
        }

        @Override
        public String toString() {
            return "RevocationResult [requestContext=" + requestContext + ", succeeded=" + succeeded + ", errorCode=" + errorCode + ", errorMessage="
                    + errorMessage + "]";
        }
    }

    private final AzureAuthenticator azureCredentials;
    private final HttpClientWithProxySupport client;
    private final String clientIdAndVersion;
    private String pkiConnectorUrl;
    private String scepRequestValidationUrl;
    private AzureAuthenticator.BearerToken lastToken = null; // set before API is called and cached
    private String graphResourceUrl;
    private String graphResourceVersion;
    private String intuneResourceUrl;

    /**
     * It's expected that clients will use the Builder class to build this.
     *
     * @param azureCredentials object used to get a bearer token for Azure authentication
     * @param clientIdAndVersion a string passed to Azure for use in tracing and logging
     * @param client Client used to send HTTP requests to/from Azure
     * @param graphResourceVersion
     * @param graphResourceUrl
     */
    IntuneRestApi(final AzureAuthenticator azureCredentials, final String clientIdAndVersion, HttpClientWithProxySupport client,
            String graphResourceUrl, String graphResourceVersion, String intuneResourceUrl) {
        this.azureCredentials = azureCredentials;
        this.client = client;
        this.clientIdAndVersion = clientIdAndVersion;
        this.graphResourceUrl = graphResourceUrl;
        this.graphResourceVersion = graphResourceVersion;
        this.intuneResourceUrl = intuneResourceUrl;
        logger.info("Intune client created.  Credentials = " + azureCredentials + " clientIdAndVersion = " + clientIdAndVersion + " client = "
                + client + " graphResourceUrl = " + graphResourceUrl + " graphResourceVersion = " + graphResourceVersion + " intuneResourceUrl = "
                + intuneResourceUrl);
    }

    /**
     * @throws IOException
     * @throws AzureException
     */
    private void refreshServiceUrls() throws IOException, AzureException {
        if (pkiConnectorUrl != null && scepRequestValidationUrl != null) {
            logger.debug("Intune endpoint URLs known.");
            return;
        }

        String graphResourceUrlWithProtocol = graphResourceUrl;
        if (!graphResourceUrlWithProtocol.startsWith("http:") && !graphResourceUrlWithProtocol.startsWith("https:")) {
            graphResourceUrlWithProtocol = "https://" + graphResourceUrl;
        }
        String graphScope = new URL(new URL(graphResourceUrlWithProtocol), "/.default").toString();
        final AzureAuthenticator.BearerToken token = azureCredentials.getBearerTokenForResource(graphScope);

        String graphQueryUrl = (graphResourceUrlWithProtocol.endsWith("/") ? graphResourceUrlWithProtocol : graphResourceUrlWithProtocol + "/")
                + graphResourceVersion + "/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints";

        // get the URL for intune by querying graph API
        try (CloseableHttpClient httpClient = client.getClient()) {
            logger.debug("Getting Intune endpoint URLs from Microsoft graph " + graphQueryUrl);
            final HttpGet request = client.getGet(graphQueryUrl);

            request.addHeader("Authorization", "Bearer " + token.getToken());
            request.addHeader("client-request-id", getRequestId());
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Graph response:" + response.getStatusLine());

                throwOnFailure(graphQueryUrl, response);
                final JSONObject servicePrincipals = toJson(response);
                final JSONArray servicePrincipalList = (JSONArray) servicePrincipals.get("value");
                for (final Object o : servicePrincipalList) {
                    final JSONObject servicePrincipal = (JSONObject) o;
                    if ("PkiConnectorFEService".equals(servicePrincipal.get("providerName"))) {
                        pkiConnectorUrl = (String) servicePrincipal.get("uri");
                    } else if ("ScepRequestValidationFEService".equals(servicePrincipal.get("providerName"))) {
                        scepRequestValidationUrl = (String) servicePrincipal.get("uri");
                    }
                }

                if (pkiConnectorUrl == null) {
                    logger.error("PkiConnectorFEService endpoint not found");
                    throw new AzureException("PkiConnectorFEService endpoint not found");
                }
                if (scepRequestValidationUrl == null) {
                    logger.error("ScepRequestValidationFEService endpoint not found");
                    throw new AzureException("ScepRequestValidationFEService endpoint not found");
                }

                logger.debug("PkiConnectorFEService endpoint = " + pkiConnectorUrl);
                logger.debug("ScepRequestValidationFEService endpoint = " + scepRequestValidationUrl);
            }
        }
    }

    private void throwOnFailure(final String url, final CloseableHttpResponse response) throws AzureException {
        final int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode < 200 || statusCode >= 300) {
            final String message = "Request to " + url + " returned " + response.getStatusLine();
            logger.error(message);
            // renew credentials after failures
            lastToken = null;
            if (logger.isDebugEnabled()) {
                try (InputStream content = response.getEntity().getContent()) {
                    logger.debug("Response contents:" + IOUtils.toString(content, StandardCharsets.UTF_8));
                } catch (UnsupportedOperationException | IOException e) {
                    logger.debug("Unable to read response contents");
                }
            }
            throw new AzureException(message);
        }
    }

    private static String getRequestId() {
        return Long.toString(new Random().nextLong());
    }

    /**
     * Connect to Intune and download the revocation requests for this tenant.
     * @param maxRequests
     * @param issuerName May be null.  If specified, only return revocations for issuerName.  If null, return all requests for this tenant.
     *
     * @return List of revocation results to perform
     *
     * @throws IOException
     * @throws AzureException
     */
    public List<RevocationRequest> downloadRevocationRequests(int maxRequests, String issuerName) throws IOException, AzureException {
        refreshServiceUrls();
        HashMap<String, Object> downloadParameters = new HashMap<>();
        downloadParameters.put("maxRequests", maxRequests);
        downloadParameters.put("issuerName", issuerName);
        StringWriter downloadParametersString = new StringWriter();
        writeJSONString(Collections.singletonMap("downloadParameters", downloadParameters), downloadParametersString);

        if (lastToken == null || lastToken.isExpired()) {
            lastToken = azureCredentials.getBearerTokenForResource(getIntuneScope());
        }

        // get the list of revocation requests
        try (CloseableHttpClient httpClient = client.getClient()) {
            final String uri = pkiConnectorUrl + "/CertificateAuthorityRequests/downloadRevocationRequests";
            logger.debug("Downloading Intune revocation requests from " + uri);
            final HttpPost request = client.getPost(uri);
            request.addHeader("Authorization", "Bearer " + lastToken.getToken());
            request.addHeader("client-request-id", getRequestId());
            request.addHeader("content-type", "application/json; charset=utf-8");
            request.addHeader("api-version", INTUNE_API_VERSION);
            request.addHeader("UserAgent", clientIdAndVersion);
            request.setEntity(new StringEntity(downloadParametersString.toString(), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Intune response:" + response.getStatusLine());

                throwOnFailure(uri, response);
                final ArrayList<RevocationRequest> out = new ArrayList<>();
                final JSONObject results = toJson(response);
                for (final Object o : (JSONArray) results.get("value")) {
                    out.add(toRevocationRequest((JSONObject) o));
                }
                if (logger.isDebugEnabled()) {
                    out.forEach(logger::debug);
                }
                return out;
            }
        }
    }

    private JSONObject toJson(CloseableHttpResponse response) throws IOException {
        final JSONObject results;
        try (InputStream content = response.getEntity().getContent()) {
            results = (JSONObject) JSONValue.parse(new InputStreamReader(content));
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private static JSONObject toJsonObject(final RevocationResult result) {
        final JSONObject out = new JSONObject();
        out.put("requestContext", result.requestContext);
        out.put("succeeded", result.succeeded);
        out.put("errorCode", result.errorCode);
        out.put("errorMessage", result.errorMessage);
        return out;
    }

    public void uploadResults(final Collection<RevocationResult> results) throws IOException, AzureException {
        refreshServiceUrls();

        if (logger.isDebugEnabled()) {
            logger.debug("Uploading revocation results to Intune:");
            results.forEach(logger::debug);
        }

        // serialize to JSON
        final StringWriter jsonStringWriter = new StringWriter();
        final List<JSONObject> resultsList = results.stream().map(IntuneRestApi::toJsonObject).collect(Collectors.toList());
        writeJSONString(Collections.singletonMap("results", resultsList), jsonStringWriter);
        String jsonString = jsonStringWriter.toString();
        if (logger.isDebugEnabled()) {
            logger.debug("Revocation results update json = " + jsonString);
        }

        if (lastToken == null || lastToken.isExpired()) {
            lastToken = azureCredentials.getBearerTokenForResource(getIntuneScope());
        }

        // get the list of revocation requests
        try (CloseableHttpClient httpClient = client.getClient()) {
            final String uri = pkiConnectorUrl + "/CertificateAuthorityRequests/uploadRevocationResults";
            logger.debug("Uploading Intune revocation results to " + uri);
            final HttpPost request = client.getPost(uri);
            request.addHeader("Authorization", "Bearer " + lastToken.getToken());
            request.addHeader("client-request-id", getRequestId());
            request.addHeader("content-type", "application/json; charset=utf-8");
            request.addHeader("api-version", INTUNE_API_VERSION);
            request.addHeader("UserAgent", clientIdAndVersion);
            request.setEntity(new StringEntity(jsonString, StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Intune response:" + response.getStatusLine());
                throwOnFailure(uri, response);
                final JSONObject status = toJson(response);
                if (!(Boolean) status.get("value")) {
                    throw new AzureException("Error uploading revocation results to Azure");
                }
            }
        }
    }

    public void validateRequest(final String transactionId, final String pemEncodedRequest) throws IOException, AzureException {
        refreshServiceUrls();

        // serialize to JSON
        final StringWriter jsonString = new StringWriter();
        final HashMap<String, String> requestInfo = new HashMap<>();
        requestInfo.put("transactionId", transactionId);
        requestInfo.put("certificateRequest", pemEncodedRequest);
        requestInfo.put("callerInfo", clientIdAndVersion);
        writeJSONString(Collections.singletonMap("request", requestInfo), jsonString);

        if (lastToken == null || lastToken.isExpired()) {
            lastToken = azureCredentials.getBearerTokenForResource(getIntuneScope());
        }

        // get the list of revocation requests
        try (CloseableHttpClient httpClient = client.getClient()) {
            final String uri = scepRequestValidationUrl + "/ScepActions/validateRequest";
            logger.debug("Validating pkcs10 request with " + uri);
            final HttpPost request = client.getPost(uri);
            request.addHeader("Authorization", "Bearer " + lastToken.getToken());
            request.addHeader("client-request-id", getRequestId());
            request.addHeader("content-type", "application/json; charset=utf-8");
            request.addHeader("api-version", INTUNE_API_VERSION);
            request.addHeader("UserAgent", clientIdAndVersion);
            request.setEntity(new StringEntity(jsonString.toString(), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Intune response:" + response.getStatusLine());
                throwOnFailure(uri, response);
                final JSONObject status = toJson(response);
                final String codeString = (String) status.get("code");
                if (!codeString.equals("Success")) {
                    final String errorDescription = (String) status.get("errorDescription");
                    final String message = "Error validating SCEP request: " + codeString + ":" + errorDescription;
                    logger.error(message);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failing transaction id = " + transactionId);
                        logger.debug("Failing PKCS10 = " + pemEncodedRequest);
                    }
                    throw new AzureException(message);
                }
            }
        }
    }

    public void sendFailureNotification(String transactionId, String pemEncodedRequest, long hResult, String errorDescription)
            throws IOException, AzureException {
        refreshServiceUrls();

        // serialize to JSON
        final StringWriter jsonString = new StringWriter();
        final HashMap<String, Object> requestInfo = new HashMap<>();
        requestInfo.put("transactionId", transactionId);
        requestInfo.put("certificateRequest", pemEncodedRequest);
        requestInfo.put("hResult", hResult);
        requestInfo.put("errorDescription", errorDescription);
        requestInfo.put("callerInfo", clientIdAndVersion);
        if (logger.isDebugEnabled()) {
            logger.debug("Sending SCEP failure notification: " + requestInfo);
        }
        writeJSONString(Collections.singletonMap("notification", requestInfo), jsonString);

        if (lastToken == null || lastToken.isExpired()) {
            lastToken = azureCredentials.getBearerTokenForResource(getIntuneScope());
        }

        // get the list of revocation requests
        try (CloseableHttpClient httpClient = client.getClient()) {
            final String uri = scepRequestValidationUrl + "/ScepActions/failureNotification";
            logger.debug("Validating pkcs10 request with " + uri);
            final HttpPost request = client.getPost(uri);
            request.addHeader("Authorization", "Bearer " + lastToken.getToken());
            request.addHeader("client-request-id", getRequestId());
            request.addHeader("content-type", "application/json; charset=utf-8");
            request.addHeader("api-version", INTUNE_API_VERSION);
            request.addHeader("UserAgent", clientIdAndVersion);
            request.setEntity(new StringEntity(jsonString.toString(), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Intune response:" + response.getStatusLine());
                throwOnFailure(uri, response);
                final JSONObject status;
                try (InputStream content = response.getEntity().getContent()) {
                    status = (JSONObject) JSONValue.parse(new InputStreamReader(content));
                }

                final String codeString = (String) status.get("code");
                if (!codeString.equals("Success")) {
                    final String notificationErrorDescription = (String) status.get("errorDescription");
                    final String message = "Error validating SCEP request: " + codeString + ":" + notificationErrorDescription;
                    logger.error(message);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failing transaction id = " + transactionId);
                        logger.debug("Failing PKCS10 = " + pemEncodedRequest);
                    }
                    throw new AzureException(message);
                }
            }
        }
    }

    public void sendSuccessNotification(String transactionId, String pemEncodedRequest, String certThumbprint, String certSerialNumber,
            String certExpirationDate, String certIssuingAuthority, String caConfiguration, String certificateAuthority)
            throws IOException, AzureException {
        refreshServiceUrls();

        // serialize to JSON
        final StringWriter jsonString = new StringWriter();
        final HashMap<String, Object> requestInfo = new HashMap<>();
        requestInfo.put("transactionId", transactionId);
        requestInfo.put("certificateRequest", pemEncodedRequest);
        requestInfo.put("certificateThumbprint", certThumbprint);
        requestInfo.put("certificateSerialNumber", certSerialNumber);
        requestInfo.put("certificateExpirationDateUtc", certExpirationDate);
        requestInfo.put("issuingCertificateAuthority", certIssuingAuthority);
        requestInfo.put("callerInfo", clientIdAndVersion);
        requestInfo.put("caConfiguration", caConfiguration);
        requestInfo.put("certificateAuthority", certificateAuthority);
        if (logger.isDebugEnabled()) {
            logger.debug("Sending SCEP success notification: " + requestInfo);
        }
        writeJSONString(Collections.singletonMap("notification", requestInfo), jsonString);

        if (lastToken == null || lastToken.isExpired()) {
            lastToken = azureCredentials.getBearerTokenForResource(getIntuneScope());
        }

        // get the list of revocation requests
        try (CloseableHttpClient httpClient = client.getClient()) {
            final String uri = scepRequestValidationUrl + "/ScepActions/successNotification";
            logger.debug("Validating pkcs10 request with " + uri);
            final HttpPost request = client.getPost(uri);
            request.addHeader("Authorization", "Bearer " + lastToken.getToken());
            request.addHeader("client-request-id", getRequestId());
            request.addHeader("content-type", "application/json; charset=utf-8");
            request.addHeader("api-version", INTUNE_API_VERSION);
            request.addHeader("UserAgent", clientIdAndVersion);
            request.setEntity(new StringEntity(jsonString.toString(), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                logger.debug("Intune response:" + response.getStatusLine());
                throwOnFailure(uri, response);
                final JSONObject status = toJson(response);

                final String codeString = (String) status.get("code");
                if (!codeString.equals("Success")) {
                    final String notificationErrorDescription = (String) status.get("errorDescription");
                    final String message = "Error validating SCEP request: " + codeString + ":" + notificationErrorDescription;
                    logger.error(message);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failing transaction id = " + transactionId);
                        logger.debug("Failing PKCS10 = " + pemEncodedRequest);
                    }
                    throw new AzureException(message);
                }
            }
        }
    }

    private RevocationRequest toRevocationRequest(final JSONObject revocationRequest) {
        //@formatter:off
        return new RevocationRequest(
                (String) revocationRequest.get("requestContext"),
                (String) revocationRequest.get("serialNumber"),
                (String) revocationRequest.get("issuerName"),
                (String) revocationRequest.get("caConfiguration"));
        //@formatter:on
    }

    public String getIntuneScope() {
        return getIntuneResourceUrl() + "/.default";
    }

    private String getIntuneResourceUrl() {
        return intuneResourceUrl;
    }

    /**
     * Builder class for IntuneRestApi
     */
    public static class Builder {

        private String proxyPassword = null;
        private String proxyHost = null;
        private Integer proxyPort = null;
        private String proxyUser = null;
        private String clientSecret = null;
        private String clientId = null;
        private String tenantId = null;
        private String clientIdAndVersion = null;
        private String azureLoginUrl = AzureAuthenticator.DEFAULT_AZURE_LOGIN_URL;
        private PrivateKey clientKey = null;
        private X509Certificate clientCertificate = null;
        private String graphResourceUrl = DEFAULT_GRAPH_URL;
        private String graphResourceVersion = DEFAULT_GRAPH_VERSION;
        private String intuneResourceUrl = DEFAULT_INTUNE_URL;

        /**
         * Create a builder for constructing an IntuneRestApi.  These fields are always needed.
         * Note that clientIdAndVersion is just an informational string and in theory can be
         * used on the Azure side to trace operations. GlobalConfiguration.EJBCA_VERSION
         * is a reasonable value for it.
         *
         * @param tenantId azure tenant id
         * @param applicationId id of Azure registered application
         * @param clientIdAndVersion informational string for tracing operations
         */
        public Builder(String tenantId, String applicationId, String clientIdAndVersion) {
            this.tenantId = tenantId;
            this.clientId = applicationId;
            this.clientIdAndVersion = clientIdAndVersion;
        }

        public IntuneRestApi build() {

            HttpClientWithProxySupport client;
            if (proxyHost != null) {
                Preconditions.checkNotNull(proxyPort);
                if (proxyUser != null) {
                    Preconditions.checkNotNull(proxyPassword);
                    client = HttpClientWithProxySupport.basicAuthProxy(proxyHost, proxyPort, proxyUser, proxyPassword);
                } else {
                    client = HttpClientWithProxySupport.openProxy(proxyHost, proxyPort);
                }
            } else {
                client = HttpClientWithProxySupport.noProxy();
            }

            Preconditions.checkNotNull(tenantId);
            Preconditions.checkNotNull(clientId);
            AzureAuthenticator credentials;
            if (clientSecret != null) {
                credentials = new AzureClientAndSecretAuthenticator(azureLoginUrl, tenantId, clientId, clientSecret, client);
            } else {
                Preconditions.checkNotNull(clientCertificate);
                Preconditions.checkNotNull(clientKey);
                credentials = new AzureCertificateAuthenticator(azureLoginUrl, tenantId, clientId, clientCertificate, clientKey, client);
            }

            return new IntuneRestApi(credentials, clientIdAndVersion, client, graphResourceUrl, graphResourceVersion, intuneResourceUrl);
        };

        public Builder withGraphResourceUrl(String graphResourceUrl) {
            this.graphResourceUrl = graphResourceUrl;
            return this;
        }

        public Builder withGraphResourceVersion(String graphResourceVersion) {
            this.graphResourceVersion = graphResourceVersion;
            return this;
        }

        public Builder withProxyPassword(String proxyPassword) {
            this.proxyPassword = proxyPassword;
            return this;
        }

        public Builder withAzureLoginUrl(String azureLoginUrl) {
            this.azureLoginUrl = azureLoginUrl;
            return this;
        }

        public Builder withProxyUser(String proxyUser) {
            this.proxyUser = proxyUser;
            return this;
        }

        public Builder withProxyHost(String proxyHost) {
            this.proxyHost = proxyHost;
            return this;
        }

        public Builder withProxyPort(int proxyPort) {
            this.proxyPort = proxyPort;
            return this;
        }

        public Builder withClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder withClientKey(PrivateKey clientKey) {
            this.clientKey = clientKey;
            return this;
        }

        public Builder withClientCertificate(X509Certificate clientCertificate) {
            this.clientCertificate = clientCertificate;
            return this;
        }

        public Builder withIntuneResourceUrl(String intuneUrl) {
            this.intuneResourceUrl = intuneUrl;
            return this;
        }
    };
}
