/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.config;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

import org.apache.log4j.Logger;
import org.cesecore.accounts.AccountBindingException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBinding;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBindingFactory;
import org.ejbca.core.protocol.dnssec.DnsSecDefaults;

/**
 * Configuration used by specifying the configurationId as part of the request URL path.
 */
public class AcmeConfiguration extends UpgradeableDataHashMap implements Serializable {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(AcmeConfiguration.class);
    
    private static final long serialVersionUID = 1L;
    
    protected static final InternalResources intres = InternalResources.getInstance();
    
    protected static final float LATEST_VERSION = 5;
    
    private String configurationId = null;
    private List<String> caaIdentities = new ArrayList<>();

    private static final String KEY_REQUIRE_EXTERNAL_ACCOUNT_BINDING = "requireExternalAccountBinding";
    private static final String KEY_EXTERNAL_ACCOUNT_BINDING = "externalAccountBinding";
    private static final String KEY_PRE_AUTHORIZATION_ALLOWED = "preAuthorizationAllowed";
    private static final String KEY_END_ENTITY_PROFILE_ID = "endEntityProfileId";
    private static final String KEY_VALIDATION_HTTP_CALLBACK_URL_TEMPLATE = "valiationHttpCallbackUrlTemplate";
    private static final String KEY_TERMS_OF_SERVICE_URL = "termsOfServiceUrl";
    private static final String KEY_TERMS_OF_SERVICE_CHANGE_URL = "termsOfServiceChangeUrl";
    private static final String KEY_WEB_SITE_URL = "webSiteUrl";
    private static final String KEY_ORDER_VALIDITY = "orderValidity";
    private static final String KEY_PRE_AUTHORIZATION_VALIDITY = "preAuthorizationValidity";
    private static final String KEY_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED = "wildcardCertificateIssuanceAllowed";
    private static final String KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED = "wildcardWithHttp01ChallengeAllowed";
    private static final String KEY_DNS_RESOLVER = "dnsResolver";
    private static final String KEY_DNSSEC_TRUST_ANCHOR = "dnssecTrustAnchor";
    private static final String KEY_DNS_PORT = "dnsPort";
    private static final String KEY_USE_DNSSEC_VALIDATION = "useDnssecValidation";
    private static final String KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL = "termsOfServiceRequireNewApproval";
    private static final String KEY_AGREE_TO_NEW_TERMS_OF_SERVICE_ALLOWED = "agreeToNewTermsOfServiceAllowed";
    private static final String DNS_RESOLVER_DEFAULT = "8.8.8.8";
    private static final int DNS_SERVER_PORT_DEFAULT = 53;
    private static final String KEY_RETRY_AFTER = "retryAfter";

    private static final int DEFAULT_END_ENTITY_PROFILE_ID = EndEntityConstants.NO_END_ENTITY_PROFILE;
    private static final boolean DEFAULT_REQUIRE_EXTERNAL_ACCOUNT_BINDING = false;
    private static final boolean DEFAULT_PRE_AUTHORIZATION_ALLOWED = false;
    private static final boolean DEFAULT_REQUIRE_NEW_APPROVAL = true;
    private static final boolean DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED = true;
    private static final boolean DEFAULT_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED = false;
    private static final boolean DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED = true;
    
    private static final String DEFAULT_TERMS_OF_SERVICE_URL = "https://example.com/acme/terms";
    private static final String DEFAULT_TERMS_OF_SERVICE_CHANGE_URL = "https://example.com/acme/termsChanged";
    private static final String DEFAULT_WEBSITE_URL = "https://www.example.com/";
    private static final long DEFAULT_ORDER_VALIDITY = 3600000L;
    
    private static final boolean DEFAULT_USE_DNSSEC_VALIDATION = true;

    public AcmeConfiguration() {}

    public AcmeConfiguration(final Object upgradeableDataHashMapData) {
        super.loadData(upgradeableDataHashMapData);
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        if (Float.compare(getLatestVersion(), getVersion()) > 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("acmeconfiguration.upgrade", getVersion()));
            // v5. Added configurable order validity.
            setOrderValidity(DEFAULT_ORDER_VALIDITY);
            // v4. Added wildcard certificate issuance with http-01 challenge allowed.
            setWildcardWithHttp01ChallengeAllowed(DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED);
            // v3. Change of ToS URL is set to ToS URL and MUST be changed by the user if feature is used (but 
            // it's a required field on GUI).
            setTermsOfServiceChangeUrl(getTermsOfServiceUrl());
            setAgreeToNewTermsOfServiceAllowed(DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED);
            // v2. ACME external account binding implementation.
            try {
                if (getExternalAccountBinding() == null) {
                    setExternalAccountBinding(AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation());
                }
            } catch (AccountBindingException e) {
                log.error("Could not upgrade ACME configuration with default ACME EAB implementation: " + e.getMessage());
            }
            data.put(VERSION, LATEST_VERSION);
        }
    }

    /** @return the configuration ID as used in the request URL path */
    public String getConfigurationId() { return configurationId; }
    public void setConfigurationId(final String configurationId) { this.configurationId = configurationId; }

    /**
     * External Account Binding
     * https://tools.ietf.org/html/rfc8555#section-7.3.4
     *
     * NOTE: Don't expose this as client configuration yet. The current implementation has the code for validation
     *       using a dummy HMAC, but will strip this info anyway from the actual account.
     *
     * @return true if an the server should enforce external account bindings.
     */
    public boolean isRequireExternalAccountBinding() {
        return Boolean.valueOf((String)super.data.get(KEY_REQUIRE_EXTERNAL_ACCOUNT_BINDING));
    }
    public void setRequireExternalAccountBinding(final boolean requireExternalAccountBinding) {
        super.data.put(KEY_REQUIRE_EXTERNAL_ACCOUNT_BINDING, String.valueOf(requireExternalAccountBinding));
    }

    @SuppressWarnings("unchecked")
    public AcmeExternalAccountBinding getExternalAccountBinding() throws AccountBindingException {
        if (data.get(KEY_EXTERNAL_ACCOUNT_BINDING) instanceof LinkedHashMap) {
            final LinkedHashMap<Object,Object> eabData = (LinkedHashMap<Object,Object>) data.get(KEY_EXTERNAL_ACCOUNT_BINDING);
            final AcmeExternalAccountBinding eab = AcmeExternalAccountBindingFactory.INSTANCE.getArcheType((String) eabData.get("typeIdentifier"));
            eab.setDataMap(eabData);
            return eab;
        }
        return null;
    }

    public void setExternalAccountBinding(final AcmeExternalAccountBinding eab) {
        if (eab != null) {
            data.put(KEY_EXTERNAL_ACCOUNT_BINDING, eab.clone().getDataMap());
        }
    }

    /**
     * Pre-Authorization
     * https://tools.ietf.org/html/rfc8555#section-7.4.1
     * 
     * "If a CA wishes to allow pre-authorization within ACME, it can offer a "new authorization" resource in its
     * directory by adding the field "newAuthz" with a URL for the new authorization resource."
     */
    public boolean isPreAuthorizationAllowed() {
        return Boolean.valueOf((String)super.data.get(KEY_PRE_AUTHORIZATION_ALLOWED));
    }
    public void setPreAuthorizationAllowed(final boolean preAuthorizationAllowed) {
        super.data.put(KEY_PRE_AUTHORIZATION_ALLOWED, String.valueOf(preAuthorizationAllowed));
    }

    /** @return the End Entity Profile ID whos default Certificate Profile and CA will be used for issuing */
    public int getEndEntityProfileId() {
        final Integer endEntityProfileId = (Integer) super.data.get(KEY_END_ENTITY_PROFILE_ID);
        return endEntityProfileId==null ? EndEntityConstants.NO_END_ENTITY_PROFILE : endEntityProfileId.intValue();
    }
    public void setEndEntityProfileId(final int endEntityProfileId) {
        super.data.put(KEY_END_ENTITY_PROFILE_ID, Integer.valueOf(endEntityProfileId));
    }

    /** @return the pattern we will use for "http-01" challenge validation. Defaults to example from RFC draft 06. */
    public String getValidationHttpCallBackUrlTemplate() {
        final String urlTemplate = (String) super.data.get(KEY_VALIDATION_HTTP_CALLBACK_URL_TEMPLATE);
        return urlTemplate==null ? "http://{identifer}/.well-known/acme-challenge/{token}" : urlTemplate;
    }
    public void setValidationHttpCallBackUrlTemplate(final String urlTemplate) {
        super.data.put(KEY_VALIDATION_HTTP_CALLBACK_URL_TEMPLATE, urlTemplate);
    }

    /** @return an URL of where the current Terms Of Services can be located. */
    public String getTermsOfServiceUrl() {
        return (String) super.data.get(KEY_TERMS_OF_SERVICE_URL);
    }
    
    public void setTermsOfServiceUrl(final String termsOfServiceUrl) {
        super.data.put(KEY_TERMS_OF_SERVICE_URL, termsOfServiceUrl);
    }
    
    /** @return a URL pointing to a location where advice how to agree to a new terms Of services version can be found. */
    public String getTermsOfServiceChangeUrl() {
        return (String) super.data.get(KEY_TERMS_OF_SERVICE_CHANGE_URL);
    }
    
    public void setTermsOfServiceChangeUrl(final String url) {
        super.data.put(KEY_TERMS_OF_SERVICE_CHANGE_URL, url);
    }
    
    /** @return the web site URL presented in the directory meta data */
    public String getWebSiteUrl() {
        return (String) super.data.get(KEY_WEB_SITE_URL);
    }
    public void setWebSiteUrl(final String webSiteUrl) {
        super.data.put(KEY_WEB_SITE_URL, webSiteUrl);
    }

    public List<String> getCaaIdentities() {
        return caaIdentities;
    }

    public void setCaaIdentities(final List<String> caaIdentities) {
        this.caaIdentities = caaIdentities;
    }

    /** @return how long a new order will be valid for in milliseconds */
    public long getOrderValidity() {
        final Long orderValidity = (Long) data.get(KEY_ORDER_VALIDITY);
        return Objects.isNull(orderValidity) ? DEFAULT_ORDER_VALIDITY : orderValidity;
    }
    public void setOrderValidity(final long orderValidity) {
        super.data.put(KEY_ORDER_VALIDITY, orderValidity);
    }

    /** @return how long a new pre-authorizations will be valid for in milliseconds */
    public long getPreAuthorizationValidity() {
        final Long preAuthorizationValidity = (Long) super.data.get(KEY_PRE_AUTHORIZATION_VALIDITY);
        return preAuthorizationValidity==null ? 24*3600000L : preAuthorizationValidity.intValue();
    }
    public void setPreAuthorizationValidity(final int preAuthorizationValidity) {
        super.data.put(KEY_PRE_AUTHORIZATION_VALIDITY, Long.valueOf(preAuthorizationValidity));
    }

    /** @return the number of required challenges that needs to be fulfilled in order to grant authorization for an identifier */
    public int getValidChallengesPerAuthorization() {
        return 1;
    }

    public boolean isWildcardCertificateIssuanceAllowed() {
        return Boolean.valueOf((String) super.data.get(KEY_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED));
    }

    public void setWildcardCertificateIssuanceAllowed(final boolean wildcardCertificateIssuanceAllowed) {
        super.data.put(KEY_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED, String.valueOf(wildcardCertificateIssuanceAllowed));
    }
    
    public boolean isWildcardWithHttp01ChallengeAllowed() {
        return Boolean.valueOf((String) super.data.get(KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED));
    }

    public void setWildcardWithHttp01ChallengeAllowed(final boolean allowed) {
        super.data.put(KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED, String.valueOf(allowed));
    }

    public String getDnssecTrustAnchor() {
        return (String) super.data.get(KEY_DNSSEC_TRUST_ANCHOR);
    }

    public void setDnssecTrustAnchor(String dnssecTrustAnchor) {
        super.data.put(KEY_DNSSEC_TRUST_ANCHOR, String.valueOf(dnssecTrustAnchor));
    }

    public String getDnsResolver() {
        return (String) super.data.get(KEY_DNS_RESOLVER);
    }

    public void setDnsResolver(String dnsResolver) {
        super.data.put(KEY_DNS_RESOLVER, String.valueOf(dnsResolver));
    }
    
    public int getDnsPort() {
        final Integer dnsPort = (Integer) super.data.get(KEY_DNS_PORT);
        return dnsPort != null ? dnsPort : DNS_SERVER_PORT_DEFAULT;
    }
    
    public void setDnsPort(final int dnsPort) {
        super.data.put(KEY_DNS_PORT, dnsPort);
    }
    
    public int getRetryAfter() {
        final Integer retryAfter = (Integer)data.get(KEY_RETRY_AFTER);
        return Objects.isNull(retryAfter) ? 0 : retryAfter.intValue();
    }
    
    public void setRetryAfter(final int retryAfter) {
        data.put(KEY_RETRY_AFTER, retryAfter);
    }
    
    public boolean isTermsOfServiceRequireNewApproval() {
        return Boolean.valueOf((String) super.data.get(KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL));
    }
    
    public void setTermsOfServiceRequireNewApproval(boolean termsOfServiceRequireNewApproval) {
        super.data.put(KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL, String.valueOf(termsOfServiceRequireNewApproval));
    }
    
    public boolean isAgreeToNewTermsOfServiceAllowed() {
        return Boolean.valueOf((String) super.data.get(KEY_AGREE_TO_NEW_TERMS_OF_SERVICE_ALLOWED));
    }
    
    public void setAgreeToNewTermsOfServiceAllowed(boolean allowed) {
        super.data.put(KEY_AGREE_TO_NEW_TERMS_OF_SERVICE_ALLOWED, String.valueOf(allowed));
    }
    
    public boolean isUseDnsSecValidation() {
        return Boolean.valueOf((String) super.data.get(KEY_USE_DNSSEC_VALIDATION));
    }
    
    public void setUseDnsSecValidation(final boolean useDnsSecValidation) {
        super.data.put(KEY_USE_DNSSEC_VALIDATION, String.valueOf(useDnsSecValidation));
    }

    /** Initializes a new acme configuration with default values. */
    public void initialize(String alias) {
        alias += ".";
        setEndEntityProfileId(DEFAULT_END_ENTITY_PROFILE_ID);
        setRequireExternalAccountBinding(DEFAULT_REQUIRE_EXTERNAL_ACCOUNT_BINDING);
        try {
            setExternalAccountBinding(AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation());
        } catch (AccountBindingException e) {
            // NOOP
        }
        setPreAuthorizationAllowed(DEFAULT_PRE_AUTHORIZATION_ALLOWED);
        setTermsOfServiceUrl(DEFAULT_TERMS_OF_SERVICE_URL);
        setTermsOfServiceChangeUrl(DEFAULT_TERMS_OF_SERVICE_CHANGE_URL);
        setTermsOfServiceRequireNewApproval(DEFAULT_REQUIRE_NEW_APPROVAL);
        setAgreeToNewTermsOfServiceAllowed(DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED);
        setWildcardCertificateIssuanceAllowed(DEFAULT_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED);
        setWildcardWithHttp01ChallengeAllowed(DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED);
        setWebSiteUrl(DEFAULT_WEBSITE_URL);
        setOrderValidity(DEFAULT_ORDER_VALIDITY);
        setDnsResolver(DNS_RESOLVER_DEFAULT);
        setDnssecTrustAnchor(DnsSecDefaults.IANA_ROOT_ANCHORS_DEFAULT);
        setDnsPort(DNS_SERVER_PORT_DEFAULT);
        setUseDnsSecValidation(DEFAULT_USE_DNSSEC_VALIDATION);
    }
}
