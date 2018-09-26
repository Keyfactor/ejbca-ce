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
import java.util.List;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.protocol.dnssec.DnsSecDefaults;

/**
 * Configuration used by specifying the configurationId as part of the request URL path.
 *
 * @version $Id$
 */
public class AcmeConfiguration extends UpgradeableDataHashMap implements Serializable {

    private static final long serialVersionUID = 1L;

    private String configurationId = null;
    private List<String> caaIdentities = new ArrayList<String>();

    private static final String KEY_REQUIRE_EXTERNAL_ACCOUNT_BINDING = "requireExternalAccountBinding";
    private static final String KEY_PRE_AUTHORIZATION_ALLOWED = "preAuthorizationAllowed";
    private static final String KEY_END_ENTITY_PROFILE_ID = "endEntityProfileId";
    private static final String KEY_VALIDATION_HTTP_CALLBACK_URL_TEMPLATE = "valiationHttpCallbackUrlTemplate";
    private static final String KEY_TERMS_OF_SERVICE_VERSION = "termsOfServiceVersion";
    private static final String KEY_TERMS_OF_SERVICE_URL = "termsOfServiceUrl";
    private static final String KEY_WEB_SITE_URL = "webSiteUrl";
    private static final String KEY_ORDER_VALIDITY = "orderValidity";
    private static final String KEY_PRE_AUTHORIZATION_VALIDITY = "preAuthorizationValidity";
    private static final String KEY_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED = "wildcardCertificateIssuanceAllowed";
    private static final String KEY_DNS_RESOLVER = "dnsResolver";
    private static final String KEY_DNSSEC_TRUST_ANCHOR = "dnssecTrustAnchor";
    private static final String KEY_DNS_PORT = "dnsPort";
    private static final String KEY_USE_DNSSEC_VALIDATION = "useDnssecValidation";
    private static final String KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL = "termsOfServiceRequireNewApproval";
    private static final String DNS_RESOLVER_DEFAULT = "8.8.8.8";
    private static final int DNS_SERVER_PORT_DEFAULT = 53;


    private static final int DEFAULT_END_ENTITY_PROFILE_ID = EndEntityConstants.NO_END_ENTITY_PROFILE;
    private static final boolean DEFAULT_REQUIRE_EXTERNAL_ACCOUNT_BINDING = false;
    private static final boolean DEFAULT_PRE_AUTHORIZATION_ALLOWED = false;
    private static final boolean DEFAULT_REQUIRE_NEW_APPROVAL = true;
    private static final boolean DEFAULT__WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED = false;
    private static final String DEFAULT_TERMS_OF_SERVICE_URL = "https://example.com/acme/terms";
    private static final String DEFAULT_WEBSITE_URL = "https://www.example.com/";
    private static final boolean DEFAULT_USE_DNSSEC_VALIDATION = true;


    public AcmeConfiguration() {}

    public AcmeConfiguration(final Object upgradeableDataHashMapData) {
        super.loadData(upgradeableDataHashMapData);
    }

    @Override
    public float getLatestVersion() {
        return 0;
    }

    @Override
    public void upgrade() {}

    /** @return the configuration ID as used in the request URL path */
    public String getConfigurationId() { return configurationId; }
    public void setConfigurationId(final String configurationId) { this.configurationId = configurationId; }

    /**
     * https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.5
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

    /**
     * https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4.1
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
        return urlTemplate==null ? "http://{identifer}:80/.well-known/acme-challenge/{token}" : urlTemplate;
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
        final Long orderValidity = (Long) super.data.get(KEY_ORDER_VALIDITY);
        return orderValidity==null ? 3600000L : orderValidity.intValue();
    }
    public void setOrderValidity(final int orderValidity) {
        super.data.put(KEY_ORDER_VALIDITY, Long.valueOf(orderValidity));
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
    
    public boolean isTermsOfServiceRequireNewApproval() {
        return Boolean.valueOf((String) super.data.get(KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL));
    }
    
    public void setTermsOfServiceRequireNewApproval(boolean termsOfServiceRequireNewApproval) {
        super.data.put(KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL, String.valueOf(termsOfServiceRequireNewApproval));
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
        setPreAuthorizationAllowed(DEFAULT_PRE_AUTHORIZATION_ALLOWED);
        setTermsOfServiceUrl(DEFAULT_TERMS_OF_SERVICE_URL);
        setTermsOfServiceRequireNewApproval(DEFAULT_REQUIRE_NEW_APPROVAL);
        setWildcardCertificateIssuanceAllowed(DEFAULT__WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED);
        setWebSiteUrl(DEFAULT_WEBSITE_URL);
        setDnsResolver(DNS_RESOLVER_DEFAULT);
        setDnssecTrustAnchor(DnsSecDefaults.IANA_ROOT_ANCHORS_DEFAULT);
        setDnsPort(DNS_SERVER_PORT_DEFAULT);
        setUseDnsSecValidation(DEFAULT_USE_DNSSEC_VALIDATION);
    }
}
