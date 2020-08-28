/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


/**
 * Class implementing a keystore on Azure Key Vault, using their REST API.
 * https://docs.microsoft.com/en-us/rest/api/keyvault/
 *
 * @version $Id$
 */
public class AzureCryptoToken extends BaseCryptoToken {

    private static final long serialVersionUID = 7719014139640717867L;

    private static final Logger log = Logger.getLogger(AzureCryptoToken.class);
    /**
     * Internal localization of logs and errors
     */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Authorization header, for a Key Vault 
     * It is possible to have multiple crypto tokens configured to multiple key vaults (with different names), because this is
     * local to this instance of CryptoToken. 
     */
    private String authorizationHeader;
    /** The same but for client secret */
    private String clientSecret;
    /** The same but for client ID */
    private String clientID;
    /** Fail fast status flag, of token is on- or off-line */
    private int status = STATUS_OFFLINE;

    /** We can make two types of requests, to different hosts/URLs, one is for the REST API requests 
     * and the other for the authorization URL we need to go to if we don't have a valid authorizationHeader
     * In the init mentioned we set some default parameters on these
     */
    private CloseableHttpClient httpClient;
    private CloseableHttpClient authHttpClient;

    /** Property for storing the key vault type in the crypto token properties.
     * Key Vault Type is the "pricing tier" as it says when creating an Azure Key Vault, it is also called SKU_TYPE somewhere else.
     * It can be either standard or premium, which translates to key types RSA/EC and RSA-HSM/EC-HSM, where the -HSM types are non-extractable HSM backed.
     */
    public static final String KEY_VAULT_TYPE = "keyVaultType";
    
    /** Property for storing the key vault name in the crypto token properties.
     * Azure Key Vault name, key vault specific, this is the string that will be part of the REST call URI
     * If KEY_VAULT_NAME contains a dot, it's assumed to be the full FQDN, i.e. keyvault-name.vault.azure-eu.net
     *   Resulting URL: https://" + KEY_VAULT_NAME/
     * If KEY_VAULT_NAME does not contains a dot, it's assumed to only be the hostname of a "default" azure FQDN, 
     *   i.e KEY_VAULT_NAME=keyvault-name, and automatically appended at the end is ".vault.azure.net"
     *   Resulting URL: https://" + KEY_VAULT_NAME + ".vault.azure.net/
     * 
     */
    public static final String KEY_VAULT_NAME = "keyVaultName";
    
    /** Property for storing the client_id used to access the key vault, in the crypto token properties.
     * Azure Key Vault client_id, key vault specific, this is the "AD user" that is authorized to connect to and use the key vault
     * The client_id can be authenticated with a secret or a certificate
     * Active Directory -> App registrations; add new registration (for example 'ejbca-vault'), gives an Application (client) ID. This is the client_id to use to authenticated
     * In the same location is your Tenant ID
     * It is recommended by MS that we should use client certificate authentication instead of id/secret. You get the id/secret or client certificate from AD.
     */ 
    public static final String KEY_VAULT_CLIENTID = "keyVaultClientID";    
    
    /** Cache for key aliases, to speed things up so we don't have to make multiple REST calls all the time to list aliases and public keys
     * We cache for a short time, 30 seconds to speed up GUI operations, but still allow for key generation on different nodes in a cluster, just leaving the 
     * other node not knowing of the new key for 30 seconds 
     */
    private KeyAliasesCache aliasCache = new KeyAliasesCache();
    
    private static volatile PublicKey ecPublicDummyKey = null;
    private static final byte[] ecPublicKeyBytes = Base64.decodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5sc" + 
            "wV+deHQeaRJQuM5DBYfee9TQn+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==");
    /** @return a dummy key (hardcoded prime256v1) to add in initial stage of caching, because we can not put anything empty in the cache, because putting null means remove...
     */
    private static final PublicKey getDummyCacheKey() {
        if (ecPublicDummyKey == null) {
            synchronized (ecPublicKeyBytes) {
                if (ecPublicDummyKey == null) {
                    ecPublicDummyKey = KeyTools.getPublicKeyFromBytes(ecPublicKeyBytes);
                }
            }
        }
        return ecPublicDummyKey;
    }

    /** get the keyVaultName, set during init of crypto token */
    private String getKeyVaultName() {
        return getProperties().getProperty(AzureCryptoToken.KEY_VAULT_NAME);
    }
    /** get the keyVaultType, set during init of crypto token */
    private String getKeyVaultType() {
        return getProperties().getProperty(AzureCryptoToken.KEY_VAULT_TYPE);
    }

    /** Construct a provider name for this instance of the crypto token. Make the name "AzureKeyVaultProvider-cryptoTokenID",
     * making it possible to have different providers for different instances of Key Vaults.
     * @param id crypto token ID
     * @return signature provider name to use for this Key Vault
     */
    private static String getAzureProviderName(int id) {
        return "AzureKeyVaultProvider-" + id;
    }
    
    // Pre-compile regexp pattern to make it more efficient
    private static final Pattern aliasPattern = Pattern.compile("^[0-9a-zA-Z-]+$");
    /** Checks that an alias name confirms to the Key Vault requirements, ^[0-9a-zA-Z-]+$
     * 
     * @param alias the alias name to check
     * @throws IllegalArgumentException in case the alias does not match ^[0-9a-zA-Z-]+$
     */
    protected static void checkAliasName(final String alias) throws IllegalArgumentException {
        if (!aliasPattern.matcher(alias).matches()) {
            throw new IllegalArgumentException("Key Vault aliases only supports numbers, letters and hyphen in alias names. Invalid name: " + alias);
        }
    }
    private static final Pattern aliasPatternPlusDot = Pattern.compile("^[0-9a-zA-Z-.]+$");
    /** Checks that a key vault name confirms to the Key Vault requirements, same as for an alias, plus dot (for when the full hostname is given).
     * 
     * @param vaultName the vault name to check
     * @throws IllegalArgumentException in case the vault name does not match ^[0-9a-zA-Z-.]+$
     */
    protected static void checkVaultName(final String vaultName) throws IllegalArgumentException {
        if (!aliasPatternPlusDot.matcher(vaultName).matches()) {
            throw new IllegalArgumentException("Key Vault names only supports numbers, letters, hyphen and dots in names. Invalid name: " + vaultName);
        }
    }
    
    @Override
    public void init(final Properties properties, final byte[] data, final int id) throws CryptoTokenOfflineException, NoSuchSlotException {

        // Create HttpClients to connect to Azure Key Vault, and Azure OAuth service (for authorization token)
        final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        final RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(10000) // 10 seconds between packets makes the HSM unusable
                .setConnectTimeout(10000) // we should not wait more than 10 seconds for a single operation, since we hash locally even signing a CRL should be fast from the HSM side
                .setConnectionRequestTimeout(10000) // getting a connection should not take more than 10 seconds
                .build();
        clientBuilder.setDefaultRequestConfig(requestConfig);
        httpClient = clientBuilder.build();
        authHttpClient = clientBuilder.build();
        
        setProperties(properties);
        log.info("Initializing Azure Key Vault: Name=" + getKeyVaultName() + ", type=" + getKeyVaultType());
        init(properties, false, id);

        final String keyVaultName = properties.getProperty(AzureCryptoToken.KEY_VAULT_NAME);
        if (keyVaultName == null) {
            throw new NoSuchSlotException("No key vault Name defined for crypto token");
        }
        // Check that key vault name does not have any bad characters, should follow the same regexp as aliases, except also allow dots
        checkVaultName(keyVaultName);
        clientID = properties.getProperty(AzureCryptoToken.KEY_VAULT_CLIENTID);
        log.info("Initializing Azure Key Vault: Type=" + properties.getProperty(AzureCryptoToken.KEY_VAULT_TYPE) + 
                ", Name=" + keyVaultName + ", clientID=" + clientID);
        
        // Install the Azure key vault signature provider for this crypto token
        Provider sigProvider = Security.getProvider(getAzureProviderName(id));
        if (sigProvider != null) {
            Security.removeProvider(getAzureProviderName(id));
        }
        sigProvider = new AzureProvider(getAzureProviderName(id));
        log.info("Adding Azure signature provider with name: " + sigProvider.getName());
        Security.addProvider(sigProvider);
        setJCAProvider(sigProvider);

        String autoPwd = BaseCryptoToken.getAutoActivatePin(properties);
        try {
            if (StringUtils.isNotEmpty(autoPwd)) {
                activate(autoPwd.toCharArray());
            }
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }

    @Override
    public int getTokenStatus() {
        // Keep status in memory. As this method is called very often we don't want to make REST calls every time
        return this.status;
    }

    @Override
    public List<String> getAliases() throws CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("getAliases called for crypto token: "+getId()+", "+getTokenName()+", "+getKeyVaultName()+", "+getKeyVaultType()+", "+authorizationHeader);
        }
        if (aliasCache.shouldCheckForUpdates(0) || aliasCache.getAllNames().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Cache is expired or empty, re-reading aliases: " + aliasCache.getAllNames().size());
            }
            final HttpGet request = new HttpGet(createFullKeyURL(null, getKeyVaultName()) + "?api-version=7.0");
            try (final CloseableHttpResponse response = azureHttpRequest(request)) {
                // Connect to Azure Key Vault and get the list of keys there.
                final InputStream is = response.getEntity().getContent();
                if (log.isDebugEnabled()) {
                    log.debug("getAliases response code: " + response.getStatusLine().getStatusCode());                    
                }
                String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("getAliases JSON response: " + json);
                }
                // Standard JSON Simple parsing, examples see https://github.com/fangyidong/json-simple
                final JSONParser jsonParser = new JSONParser();
                final JSONObject parse = (JSONObject) jsonParser.parse(json);
                if (response.getStatusLine().getStatusCode() == 200) {
                    final JSONArray value = (JSONArray) parse.get("value");
                    if (value != null) {
                        // We have some keys, lets re-fill the array
                        aliasCache.flush();
                        for (Object o : value) {
                            final JSONObject o1 = (JSONObject) o;
                            final String kid = (String) o1.get("kid");
                            // Return only the key name, which is what is after the last /.
                            final String alias = StringUtils.substringAfterLast(kid, "/");
                            if (log.isDebugEnabled()) {
                                log.debug("Adding alias to cache: '"+alias);
                            }
                            // Add a dummy public key
                            aliasCache.updateWith(alias.hashCode(), alias.hashCode(), alias, AzureCryptoToken.getDummyCacheKey());
                        }
                    }                    
                } else {
                    // Error response (not HTTP 200)
                    aliasCache.flush();
                    status = STATUS_OFFLINE; // make sure the crypto token is off-line for getTokenStatus
                    String message = "No parseable JSON error response"; // Defualt message if we have no JSON to parse
                    try {
                        if (parse != null) {
                            // Parse out the error message and skip the JSON code
                            final JSONObject value = (JSONObject) parse.get("error");
                            if (value != null) {
                                message = (String) value.get("code");
                                final String logmessage = (String) value.get("message");
                                if (log.isDebugEnabled()) {
                                    log.debug("Error code when listing aliases: " + response.getStatusLine().getStatusCode() + ", error message: " + logmessage);
                                }
                            }
                        }
                    } catch (ClassCastException e) {
                        // NOPMD: Ignore, message is above
                    }
                    throw new CryptoTokenOfflineException("Can not list keys, response code is " + response.getStatusLine().getStatusCode() + ", message: " + message);                    
                }
            } catch (IOException | ParseException | CryptoTokenAuthenticationFailedException e) {
                aliasCache.flush();
                status = STATUS_OFFLINE; // make sure the crypto token is off-line for getTokenStatus
                throw new CryptoTokenOfflineException("Exception listing keys:", e);
            }
            status = STATUS_ACTIVE; // make sure the crypto token is on-line for getTokenStatus
            return new ArrayList<>(aliasCache.getAllNames());
        } else {
           status = STATUS_ACTIVE; // make sure the crypto token is on-line for getTokenStatus
            return new ArrayList<>(aliasCache.getAllNames());
        }
        
    }

    @Override
    public void activate(final char[] authCode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        clientSecret = new String(authCode);
        log.info("Activating Key Vault Crypto Token, listing aliases: " + getKeyVaultName());
        getAliases(); // getAliases sets status to on-line if it succeeds
    }

    @Override
    public void deactivate() {
        log.debug(">deactivate");
        clientSecret = null;
        authorizationHeader = null;
        aliasCache.flush();
        status = STATUS_OFFLINE;        
    }

    @Override
    public void reset() {
        log.debug(">reset");
        clientSecret = null;
        authorizationHeader = null;
        aliasCache.flush();
    }

    @Override
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            checkAliasName(alias);
            final Map<String, Integer> nameToId = aliasCache.getNameToIdMap();
            final Integer id = nameToId.get(alias);
            if (id == null) {
                throw new KeyStoreException("Key with alias '" + alias +"', does not have an ID in our cache");
            }
            // remove the key from azure
            // https://docs.microsoft.com/en-us/rest/api/keyvault/deletekey/deletekey
            // DELETE {vaultBaseUrl}/keys/{key-name}?api-version=7.0
            final HttpDelete request = new HttpDelete(createFullKeyURL(alias, getKeyVaultName()) + "?api-version=7.0");
            try (final CloseableHttpResponse response = azureHttpRequest(request)) {
                if (response.getStatusLine().getStatusCode() != 200) {
                    final InputStream is = response.getEntity().getContent();
                    final String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("deleteEntry error JSON response: " + json);
                    }
                    throw new CryptoTokenOfflineException("Azure Crypto Token key deletion failed, JSON response: " + json);
                } else {
                    final InputStream is = response.getEntity().getContent();
                    final String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("deleteEntry success JSON response: " + json);
                    }
                    // Remove the entry from our cache
                    aliasCache.removeEntry(id);
                }
            } catch (CryptoTokenAuthenticationFailedException e) {
                throw new CryptoTokenOfflineException(e);
            }
            final String msg = intres.getLocalizedMessage("token.deleteentry", alias, getId());
            log.info(msg);
        } else {
            log.info("Trying to delete keystore entry with empty alias.");
        }
    }

    @Override
    public void generateKeyPair(KeyGenParams keyGenParams, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        generateKeyPair(keyGenParams.getKeySpecification(), alias);
        
    }
    
    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException,
            CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug(">generateKeyPair(keyspec): " + keySpec + ", " + alias);
        }
        if (StringUtils.isNotEmpty(alias)) {
            checkAliasName(alias);
            // validate that keySpec matches some of the allowed Azure Key Vault key types/lengths.
            // Allow kty RSA-HSM or EC-HSM. RSA key_size or "crv" (P-256, P-384, P-521), 
            // {"kty": "RSA-HSM", "key-size": 2048, "attributes": {"enabled": true}}
            // {"kty": "EC-HSM", "crv": "P-256", "attributes": {"enabled": true}}
            final StringBuilder str = new StringBuilder("{\"kty\": ");
            // If it is pure numeric, it is an RSA key length
            if (NumberUtils.isNumber(keySpec)) {
                String kty = "RSA-HSM";
                if (getKeyVaultType().equals("standard")) {
                    kty = "RSA";
                }
                if (log.isDebugEnabled()) {
                    log.debug("RSA keyspec is: " + keySpec + ", and key vault type is " + kty);
                }
                str.append("\"").append(kty).append("\", \"key_size\": ").append(keySpec);
            } else {
                // Must be EC?
                String kty = "EC-HSM";
                if (getKeyVaultType().equals("standard")) {
                    kty = "EC";
                }
                if (log.isDebugEnabled()) {
                    log.debug("EC keyspec is: " + keySpec + ", and key vault type is " + kty);
                }
                String azureCrv;
                if ("prime256v1".equals(keySpec) || "secp256r1".equals(keySpec) || "P-256".equals(keySpec)) {
                    azureCrv = "P-256";
                } else if ("prime384v1".equals(keySpec) || "secp384r1".equals(keySpec) || "P-384".equals(keySpec)) {
                    azureCrv = "P-384";                    
                } else if ("prime521v1".equals(keySpec) || "secp521r1".equals(keySpec) || "P-521".equals(keySpec)) {
                    azureCrv = "P-521";
                } else {
                    throw new InvalidAlgorithmParameterException("EC curve " + keySpec + " is not a valid curve for Azure Key Vault, only P-256, P-384 and P-521 is allowed");
                }
                str.append("\"").append(kty).append("\", \"crv\": \"").append(azureCrv).append("\"");
            }
            str.append(", \"attributes\": {\"enabled\": true}}");
            //  generate key in our previously created key vault.
            final HttpPost request = new HttpPost(createFullKeyURL(alias, getKeyVaultName()) + "/create?api-version=7.0");
            request.setHeader("Content-Type", "application/json");
            try {
                request.setEntity(new StringEntity(str.toString()));
                if (log.isDebugEnabled()) {
                    log.debug("Key generation request JSON: " + str.toString());
                }
            } catch (UnsupportedEncodingException e) {
                throw new InvalidAlgorithmParameterException(e);
            }
            try (final CloseableHttpResponse response = azureHttpRequest(request)) {
                final InputStream is = response.getEntity().getContent();
                final String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("generateKeyPair JSON response: " + json);
                }
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new CryptoTokenOfflineException("Azure Crypto Token key generation failed, JSON response: " + json);
                }
                // Update client key aliases next time we want to use one, could be done without having to update the whole cache, 
                // but might as well as we don't cache for too long anyhow
                aliasCache.flush();
            } catch (CryptoTokenAuthenticationFailedException | IOException e) {
                throw new CryptoTokenOfflineException(e);
            }
        } else {
            log.info("Trying to generate keys with empty alias, doing nothing.");
        }
    }

    @Override
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws
            InvalidAlgorithmParameterException, CertificateException, IOException,
            CryptoTokenOfflineException {
        log.debug(">generateKeyPair: AlgorithmParameterSpec");
        if (StringUtils.isNotEmpty(alias)) {
            throw new InvalidAlgorithmParameterException("Azure key generation with AlgorithmParameterSpec is not implemented");
        } else {
            log.info("Trying to generate keys with empty alias, doing nothing.");
        }
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("Generate key, " + algorithm + ", " + keysize + ", " + alias);
        }
        if (StringUtils.isNotEmpty(alias)) {
            throw new NoSuchAlgorithmException("Azure key generation with only keysize is not implemented");
        } else {
            log.info("Trying to generate keys with empty alias, doing nothing.");
        }
    }

    @Override
    public byte[] getTokenData() {
        // There is no data for an Azure Key Vault, only properties
        return null;
    }


    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return doPermitExtractablePrivateKey();
    }

    @Override
    public void setTokenName(String tokenName) {
        super.setTokenName(tokenName);
    }

    @Override
    public boolean isAliasUsed(String alias) {
        final Set<String> names = aliasCache.getAllNames();
        if (!names.isEmpty()) {
            boolean ret = names.contains(alias);
            if (log.isDebugEnabled()) {
                log.debug("isAliasUsed: " + ret);
            }
            return ret;
        }
        log.debug("isAliasUsed: no aliases exists, returning false");
        return false;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        // Does the alias exist?
        final PublicKey pubK = getPublicKey(alias); 
        if (pubK == null) {
            log.warn(intres.getLocalizedMessage("token.noprivate", alias));
            final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
            throw new CryptoTokenOfflineException(msg);
        }
        final String keyurl = createFullKeyURL(alias, getKeyVaultName());
        if (log.isDebugEnabled()) {
            // This is a URI for Key Vault
            log.debug("getPrivateKey: " + keyurl);
        }
        return new AzureProvider.KeyVaultPrivateKey(keyurl, pubK.getAlgorithm(), this);
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        PublicKey publicKey = null;
        if (StringUtils.isEmpty(alias)) {
            return null;
        }
        checkAliasName(alias);
        if (aliasCache.shouldCheckForUpdates(alias.hashCode()) || aliasCache.getEntry(alias.hashCode()).equals(AzureCryptoToken.getDummyCacheKey()) ) {
            if (log.isDebugEnabled()) {
                log.debug("Looking for public key with alias " + alias + ", and cache is expired or filled with dummyCacheKey. Will try to read it from Key Vault.");
            }
            try {
                // connect to Azure and retrieve public key, use empty version string to get last version (don't check for existing key versions to save a round trip)
                final HttpGet request = new HttpGet(createFullKeyURL(alias, getKeyVaultName()) + "/?api-version=7.0");
                try (final CloseableHttpResponse response = azureHttpRequest(request)) {
                    final InputStream is = response.getEntity().getContent();
                    String json = null;
                    if (is != null){
                        json = IOUtils.toString(is, StandardCharsets.UTF_8);
                        if (log.isDebugEnabled()) {
                            log.debug("getPublicKey JSON response: " + json);
                        }
                    }
                    if (response.getStatusLine().getStatusCode() == 404) {
                        log.debug("No public key found (HTTP 404 returned) with alias: " + alias);
                        return null;
                    }
                    if (response.getStatusLine().getStatusCode() != 200) {
                        log.debug("Call to get public key with alias " + alias + " returns error: " + response.getStatusLine().getStatusCode() + ", returning null.");
                        return null;
                    }
                    if (json == null) {
                        log.warn("We got HTTP 200 as response code getting public key, but no JSON content returned. Unknown error state from Key Vault. Returning null as public key (we can't find it)");
                        return null;
                    }
                    final JSONParser jsonParser = new JSONParser();
                    final JSONObject parse = (JSONObject) jsonParser.parse(json);
                    final JSONObject key = (JSONObject) parse.get("key");
                    final String kty = (String) key.get("kty");
                    if (kty.startsWith("RSA")) {
                        final String modulusB64 = (String) key.get("n");
                        final String exponentB64 = (String) key.get("e");
                        final byte[] modulus = Base64.decodeBase64(modulusB64);
                        // We want to 0-fill the returned modulus to make the BigInteger decode it properly as two-complements binary
                        final byte[] fixedModulus = new byte[modulus.length+1];
                        fixedModulus[0] = 0;
                        System.arraycopy(modulus, 0, fixedModulus, 1, modulus.length);
                        final BigInteger bigIntegerModulus = new BigInteger(fixedModulus);
                        final BigInteger bigIntegerExponent = new BigInteger(Base64.decodeBase64(exponentB64));
                        final KeyFactory rsa = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                        publicKey = rsa.generatePublic(new RSAPublicKeySpec(bigIntegerModulus, bigIntegerExponent));                    
                    } else if (kty.startsWith("EC")) {
                        final String crv = (String) key.get("crv");
                        final String xB64 = (String) key.get("x");
                        final String yB64 = (String) key.get("y");
                        final byte[] x = Base64.decodeBase64(xB64);
                        final byte[] y = Base64.decodeBase64(yB64);
                        final byte[] fixedX = new byte[x.length+1];
                        fixedX[0] = 0;
                        System.arraycopy(x, 0, fixedX, 1, x.length);
                        final BigInteger bigIntegerX = new BigInteger(fixedX);
                        byte[] fixedY = new byte[y.length+1];
                        fixedY[0] = 0;
                        System.arraycopy(y, 0, fixedY, 1, y.length);
                        final BigInteger bigIntegerY = new BigInteger(fixedY);
                        // Construct the public key object (Bouncy Castle)
                        final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(crv);
                        final java.security.spec.ECPoint p = new java.security.spec.ECPoint(bigIntegerX, bigIntegerY);
                        final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), p);
                        final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
                        final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
                        publicKey = keyfact.generatePublic(pubKey);
                    } else {
                        throw new CryptoTokenOfflineException("Unknown key type (kty) in JSON public key response (neither RSA nor EC): " + kty);
                    }
                    aliasCache.removeEntry(alias.hashCode()); // Remove any dummy entry if it is there
                    aliasCache.updateWith(alias.hashCode(), alias.hashCode(), alias, publicKey);
                }
                return publicKey;
            } catch (CryptoTokenAuthenticationFailedException | IOException | ParseException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                throw new CryptoTokenOfflineException(e);
            }            
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Getting public key from cache for alias " + alias);
            }
            return aliasCache.getEntry(alias.hashCode());
        }
    }

    /** 
     * @param alias the key alias you want to access, or null if the key alias should be left out of the returned URL
     * @return a URL to access a key (without trailing /), i.e. https://vaultname.vault.azure.net/keys/alias, or if alias is null https://vaultname.vault.azure.net/keys
     */
    protected static String createFullKeyURL(final String alias, final String vaultName) {
        final String trailing;
        if (alias == null) {
            trailing = "/keys"; 
        } else {
            trailing = "/keys/" + alias;
        }
        if (StringUtils.contains(vaultName, '.')) {
            return "https://"+ vaultName + trailing;
        } else {
            return "https://"+ vaultName + ".vault.azure.net" + trailing;
        }
    }

    /** Makes a REST API call to Azure, the REST call may need an authorizationToken, and if one does not exist (in this class) one is retrieved.
     * This means that if a valid authorizationToken exists, only one HTTP request is made, but if no valid authorizationToken exists three HTTP 
     * request are made:
     * 1. First request - response is "unauthorized" and authorization URL is parsed from the response
     * 2. Authorization request - response is an authorizationToken which is set for further use
     * 3. The First request is tried again again, with the newly fetched authorizationToken
     * 
     * Important that caller closes the response, use try-with-resource:
     *   try (CloseableHttpResponse response = azureHttpRequest(request)) {
     *    ...
     *   }
     * 
     * @param request HttpRequestBase with the either GET or POST request
     * @return CloseableHttpResponse with the response, the caller is responsible for closing it, use try-with-resource
     * @throws CryptoTokenAuthenticationFailedException if authentication to Azure failed 401 or 400 returned, or no Bearer authorization_uri exists in the response input
     * @throws CryptoTokenOfflineException if there is no clientSecret to authenticate with
     */
    CloseableHttpResponse azureHttpRequest(HttpRequestBase request) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        // Don't even try to make a request if we don't have a client secret as it is required. Better fail fast
        if (StringUtils.isEmpty(clientSecret)) {
            throw new CryptoTokenOfflineException("Crypto token with Key Vault '" + getKeyVaultName() + "' is not active, there is no client secret available: " + request.toString());
        }
        try {
            final CloseableHttpResponse response = httpRequestWithAuthHeader(request);
            final int requestStatusCode = response.getStatusLine().getStatusCode();
            if (requestStatusCode == 401) {
                log.info("Access denied calling Key Vault '" + getKeyVaultName() + "', trying to get authentication URI and fetch authorization token.");
                // This call will close the response above as quick as possible
                azureAuthorizationRequestFrom401Response(response);
                // Now we have a new fresh authorization bearer token, make the request we came to this method for again
                final CloseableHttpResponse newResponse = httpRequestWithAuthHeader(request);
                return newResponse;
            }
            return response;
        } catch (IOException | ParseException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }
    
    /** makes a HTTP request using the httpClient CloseableHttpClient of this class
     *  
     * @param request 
     * @return CloseableHttpResponse with the server response, the caller is responsible for closing it
     * @throws IOException in case HTTP request fails
     */
    private CloseableHttpResponse httpRequestWithAuthHeader(HttpRequestBase request) throws IOException {
        // Set the cached authorization token if we have any. If the token has expired, or we don't have a cached token, it will return http 401 and we can get a new one
        request.setHeader("Authorization", authorizationHeader);
        if (log.isDebugEnabled()) {
            log.debug("Request: " + request.toString());            
        }
        // Apache commons httpclient: https://hc.apache.org/httpcomponents-client-4.5.x/quickstart.html
        final CloseableHttpResponse response = httpClient.execute(request);
        if (log.isDebugEnabled()) {
            log.debug("Status code for request is: " + response.getStatusLine().getStatusCode());
            log.debug("Response.toString: " + response.toString());
        }
        return response;
    }

    /** Looks for WWW-authenticate header in the response (which must be a 401 response from Azure) and makes a call to 
     * this authentication URL to retrieve a new authorization bearer token. The received token is set in the class to be 
     * used by #httpRequestWithAuthHeader
     * 
     * @param response CloseableHttpResponse, the response that was received as part of a 401 (access denied) response from Azure
     * @throws IOException unable to make HTTP requests or close HTTP responses
     * @throws CryptoTokenAuthenticationFailedException is authentication to Azure failed 401 or 400 returned, or no Bearer authorization_uri exists in the response input
     * @throws ParseException if JSON response from Azure (response from authorization URI) can not be parsed 
     */
    private void azureAuthorizationRequestFrom401Response(CloseableHttpResponse response)
            throws CryptoTokenAuthenticationFailedException, ParseException, IOException {
        // Get bearer token (authentication token) from the response.
        final Header lastHeader = response.getLastHeader("WWW-Authenticate");
        // Close as soon as possible, we don't need this response, it's an "Error Response" for invalid_token 
        response.close();
        final HeaderElement[] elements = lastHeader.getElements();
        String oauthServiceURL = null;
        String oauthResource = null;
        for (HeaderElement element : elements) {
            final String elementName = element.getName();
            if (log.isDebugEnabled()) {
                log.debug("Investigating WWW-Authenticate HeaderElement: " + elementName);
            }
            // "Bearer authorization_uri", see https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code.
            // The actual response does not seem to match the documentation at the URL above though, as it returns for example:
            // Bearer authorization="https://login.windows.net/8375a5cc-74ce-45e8-abc1-00a87441a554"
            // resource="https://vault.azure.net"
            // We play it safe and look for both values, the doc and the actual return
            if (elementName.equals("Bearer authorization") || elementName.equals("Bearer authorization_uri")) {
                oauthServiceURL = element.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Found a Bearer authorization uri: " + oauthServiceURL);
                }
            } else if (elementName.equals("resource") || elementName.equals("resource_id")) {
                // "resource_id" to be used as resource in request, see https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code.
                oauthResource = element.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Found a resource ID: " + oauthResource);
                }
            }
        }
        if (oauthServiceURL == null) {
            throw new CryptoTokenAuthenticationFailedException("We did not find a 'Bearer authorization' uri in the WWW-Authenticate for a 401 response");
        }
        final HttpPost request = new HttpPost(oauthServiceURL + "/oauth2/token");
        final ArrayList<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("grant_type", "client_credentials"));                
        // ECA-8473: We only support client_secret for authentication right now. A more recommended way is to use certificate to authenticate.
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("client_secret", clientSecret));
        if (log.isDebugEnabled()) {
            log.debug("Using client_id and client_secret: '" + clientID + (StringUtils.isNotEmpty(clientSecret) ? ":<nologgingcleartextpasswords>'" : ":<empty pwd>"));
        }
        parameters.add(new BasicNameValuePair("resource", oauthResource));
        request.setEntity(new UrlEncodedFormEntity(parameters));
        if (log.isDebugEnabled()) {
            log.debug("Authorization request: " + request.toString());
        }
        try (final CloseableHttpResponse authResponse = authHttpClient.execute(request)) {
            final int authStatusCode = authResponse.getStatusLine().getStatusCode();
            if (log.isDebugEnabled()) {
                log.debug("Status code for authorization request is: " + authStatusCode);
                log.debug("Response.toString: " + authResponse.toString());
            }
            final String json = IOUtils.toString(authResponse.getEntity().getContent(), StandardCharsets.UTF_8);
            if (log.isDebugEnabled()) {
                log.debug("Authorization JSON response: " + json);
            }
            final JSONParser jsonParser = new JSONParser();
            final JSONObject parse = (JSONObject) jsonParser.parse(json);
            if (authStatusCode == 401 || authStatusCode == 400) { // 401 expected for no secret or wrong secret, 400 expected for wrong client_id
                authorizationHeader = null;
                log.info("Authorization denied with statusCode " + authStatusCode + " for Azure Crypto Token authentication call to URI " + request.getURI() + ", for client_id " + clientID);
                throw new CryptoTokenAuthenticationFailedException("Azure Crypto Token authorization denied, JSON response: " + json);
            } else if (authStatusCode == 200) {
                final String accessToken = (String) parse.get("access_token");
                authorizationHeader = "Bearer " + accessToken;
                if (log.isDebugEnabled()) {
                    log.debug("Authorization header from authentication response: " + authorizationHeader);
                }
            } else {
                throw new CryptoTokenAuthenticationFailedException("Azure Crypto Token authorization failed with unknown response code " + authStatusCode + ", JSON response: " + json);
            }
        }
    }


}
