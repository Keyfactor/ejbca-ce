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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.accounts.AccountBindingException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeIdentifier;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBinding;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBindingFactory;
import org.ejbca.core.protocol.dnssec.DnsSecDefaults;

/**
 * Configuration used by specifying the configurationId as part of the request URL path or as URL parameter.
 */
public class AcmeConfiguration extends UpgradeableDataHashMap implements Serializable {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(AcmeConfiguration.class);
    
    private static final long serialVersionUID = 1L;
    
    protected static final InternalResources intres = InternalResources.getInstance();
    
    protected static final float LATEST_VERSION = 11;
    
    private String configurationId = null;
    private List<String> caaIdentities = new ArrayList<>();

    private static final String KEY_RA_NAMEGENERATIONSCHEME = "ra.namegenerationscheme";
    private static final String KEY_RA_NAMEGENERATIONPARAMS = "ra.namegenerationparameters";
    private static final String KEY_RA_NAMEGENERATIONPREFIX = "ra.namegenerationprefix";
    private static final String KEY_RA_NAMEGENERATIONPOSTFIX= "ra.namegenerationpostfix";
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
    private static final String KEY_DNS_IDENTIFIER_CHALLENGE_TYPES = "dnsIdentifierChallengeTypes";
    private static final String KEY_DNS_RESOLVER = "dnsResolver";
    private static final String KEY_DNSSEC_TRUST_ANCHOR = "dnssecTrustAnchor";
    private static final String KEY_DNS_PORT = "dnsPort";
    private static final String KEY_USE_DNSSEC_VALIDATION = "useDnssecValidation";
    private static final String KEY_TERMS_OF_SERVICE_REQUIRE_NEW_APPROVAL = "termsOfServiceRequireNewApproval";
    private static final String KEY_AGREE_TO_NEW_TERMS_OF_SERVICE_ALLOWED = "agreeToNewTermsOfServiceAllowed";
    private static final String DNS_RESOLVER_DEFAULT = "8.8.8.8";
    private static final int DNS_SERVER_PORT_DEFAULT = 53;
    private static final String KEY_RETRY_AFTER = "retryAfter";
    private static final String KEY_AUTHORIZED_REDIRECT_PORTS = "authorizedRedirectPorts";
    private static final String KEY_APPROVAL_FOR_NEW_ACCOUNT_ID = "approvalForNewAccountId";
    private static final String KEY_APPROVAL_FOR_KEY_CHANGE_ID = "approvalForKeyChangeId";
    private static final String KEY_CLIENT_AUTHENTICATION_REQUIRED = "clientAuthenticationRequired";
    private static final String KEY_PREFERRED_ROOT_CA_SUBJECTDN = "preferredrootcasubjectdn";

    private static final String DEFAULT_RA_USERNAME_GENERATION_SCHEME = UsernameGeneratorParams.RANDOM;
    private static final String DEFAULT_RA_USERNAME_GENERATION_PARAMS = "CN";
    private static final String DEFAULT_RA_USERNAME_GENERATION_PREFIX = "";
    private static final String DEFAULT_RA_USERNAME_GENERATION_POSTFIX = "";
    private static final int DEFAULT_END_ENTITY_PROFILE_ID = EndEntityConstants.NO_END_ENTITY_PROFILE;
    private static final boolean DEFAULT_REQUIRE_EXTERNAL_ACCOUNT_BINDING = false;
    private static final boolean DEFAULT_PRE_AUTHORIZATION_ALLOWED = false;
    private static final boolean DEFAULT_REQUIRE_NEW_APPROVAL = true;
    private static final boolean DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED = true;
    private static final boolean DEFAULT_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED = false;
    private static final boolean DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED = true;
    public static final String DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES = "any-dns-challenge";
    
    private static final String DEFAULT_TERMS_OF_SERVICE_URL = "https://example.com/acme/terms";
    private static final String DEFAULT_TERMS_OF_SERVICE_CHANGE_URL = "https://example.com/acme/termsChanged";
    private static final String DEFAULT_WEBSITE_URL = "https://www.example.com/";
    private static final long DEFAULT_ORDER_VALIDITY = 3600000L;
    private static final String DEFAULT_AUTHORIZED_REDIRECT_PORTS = "22,25,80,443";
    private static final boolean DEFAULT_USE_DNSSEC_VALIDATION = true;
    
    public static final int DEFAULT_APPROVAL_FOR_NEW_ACCOUNT_ID = -1;
    public static final int DEFAULT_APPROVAL_FOR_KEY_CHANGE_ID = -1;
    private static final boolean DEFAULT_CLIENT_AUTHENTICATION_REQUIRED = false;
    public static final String DEFAULT_PREFERRED_ROOT_CA_SUBJECTDN = "default";

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

            // v10. Added client authentication required.
            if (data.get(KEY_CLIENT_AUTHENTICATION_REQUIRED) == null) {
                data.put(KEY_CLIENT_AUTHENTICATION_REQUIRED, String.valueOf(DEFAULT_CLIENT_AUTHENTICATION_REQUIRED));
            }
            if (data.get(KEY_PREFERRED_ROOT_CA_SUBJECTDN) == null) {
                data.put(KEY_PREFERRED_ROOT_CA_SUBJECTDN, String.valueOf(DEFAULT_PREFERRED_ROOT_CA_SUBJECTDN));
            }
            // v9. Added DNS identifier chaleenge Types selection.
            if (data.get(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES) == null) {
                data.put(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES, DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES);
            }
            // v8. ACME EAB with multiple keys -> multiple EAB.
            try {
                if (data.get(KEY_EXTERNAL_ACCOUNT_BINDING) == null) { 
                    setExternalAccountBinding(new LinkedList<AcmeExternalAccountBinding>(Collections.singletonList(
                            AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation())));
                } else if (data.get(KEY_EXTERNAL_ACCOUNT_BINDING) instanceof LinkedHashMap) {
                    final LinkedList<LinkedHashMap<Object,Object>> clones = new LinkedList<>();
                    clones.add((LinkedHashMap<Object,Object>)data.get(KEY_EXTERNAL_ACCOUNT_BINDING));
                    data.put(KEY_EXTERNAL_ACCOUNT_BINDING, clones);
                } else if (!(data.get(KEY_EXTERNAL_ACCOUNT_BINDING) instanceof List)) { // Should never happen.
                    log.error("Invalida data type during upgrade. Verify ACME configuration with alias '" + getConfigurationId() + "'");
                    setExternalAccountBinding(new LinkedList<AcmeExternalAccountBinding>(Collections.singletonList(
                            AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation())));
                }
            } catch (AccountBindingException e) {
                log.error("Could not upgrade ACME configuration with default ACME EAB implementation: " + e.getMessage());
            }
            // v7. Authorized redirect ports are not upgraded.
            if (data.get(KEY_AUTHORIZED_REDIRECT_PORTS) == null) {
                setAuthorizedRedirectPorts("");
            }
            // v6. Added approvals for account management.
            if (data.get(KEY_APPROVAL_FOR_NEW_ACCOUNT_ID) == null) {
                setApprovalForNewAccountId(DEFAULT_APPROVAL_FOR_NEW_ACCOUNT_ID);
            }
            if (data.get(KEY_APPROVAL_FOR_KEY_CHANGE_ID) == null) {
                setApprovalForKeyChangeId(DEFAULT_APPROVAL_FOR_KEY_CHANGE_ID);
            }
            if (data.get(KEY_RA_NAMEGENERATIONSCHEME) == null) {
                setRANameGenScheme(DEFAULT_RA_USERNAME_GENERATION_SCHEME);
            }
            if (data.get(KEY_RA_NAMEGENERATIONPARAMS) == null) {
                setRANameGenScheme(DEFAULT_RA_USERNAME_GENERATION_PARAMS);
            }
            if (data.get(KEY_RA_NAMEGENERATIONPREFIX) == null) {
                setRANameGenScheme(DEFAULT_RA_USERNAME_GENERATION_PREFIX);
            }
            if (data.get(KEY_RA_NAMEGENERATIONPOSTFIX) == null) {
                setRANameGenScheme(DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
            }
            // v5. Added configurable order validity.
            if (data.get(KEY_ORDER_VALIDITY) == null) {
                setOrderValidity(DEFAULT_ORDER_VALIDITY);
            }
            // v4. Added wildcard certificate issuance with http-01 challenge allowed.
            if (data.get(KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED) == null) {
                setWildcardWithHttp01ChallengeAllowed(DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED);
            }
            // v3. Change of ToS URL is set to ToS URL and MUST be changed by the user if feature is used (but 
            // it's a required field on GUI).
            if (data.get(KEY_TERMS_OF_SERVICE_CHANGE_URL) == null) {
                setTermsOfServiceChangeUrl(getTermsOfServiceUrl());
            }
            if (data.get(KEY_AGREE_TO_NEW_TERMS_OF_SERVICE_ALLOWED) == null) {
                setAgreeToNewTermsOfServiceAllowed(DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED);
            }
            // v2. ACME external account binding implementation.
            try {
                // Should not be reached anymore with version 8.
                if (data.get(KEY_EXTERNAL_ACCOUNT_BINDING) == null) { 
                    setExternalAccountBinding(new LinkedList<AcmeExternalAccountBinding>(Collections.singletonList(
                            AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation())));
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
     * Getter for RA Name Generation Scheme for given alias
     * @return name generation scheme, one of UsernameGeneratorParams.DN, UsernameGeneratorParams.RANDOM, UsernameGeneratorParams.FIXED, UUsernameGeneratorParams.SERNAME
     */
    public String getRANameGenScheme() {
        // Set default to RANDOM for aliases created before RA name generation was added.
        String value = (String) data.get(KEY_RA_NAMEGENERATIONSCHEME);
        if (value == null) {
            value = UsernameGeneratorParams.RANDOM;
        }
        return value;
    }

    /**
     * Setter for RA Name Generation Scheme
     * @param scheme one of UsernameGeneratorParams.DN, UsernameGeneratorParams.RANDOM, UsernameGeneratorParams.FIXED, UUsernameGeneratorParams.SERNAME
     */
    public void setRANameGenScheme(String scheme) {
        data.put(KEY_RA_NAMEGENERATIONSCHEME, scheme);
    }
    
    /**
     * Getter for RA Name Generation Params for given alias
     * @return RA name generation scheme DN parameters, Can be CN, UID, SN etc, or CN;UID;SN
     */
    public String getRANameGenParams() {
        return (String) data.get(KEY_RA_NAMEGENERATIONPARAMS);
    }

    /**
     * Setter for RA Name Generation Parameters
     * @param params RA name generation scheme DN parameters, Can be CN, UID, SN etc, or CN;UID;SN
     */    
    public void setRANameGenParams(String params) {
        data.put(KEY_RA_NAMEGENERATIONPARAMS, params);
    }

    /**
     * Getter for RA Name Generation Prefix for given alias
     */
    public String getRANameGenPrefix() {
        //Set default to empty String for aliases created before RA name generation was added.
        String value = (String) data.get(KEY_RA_NAMEGENERATIONPREFIX);
        if (value == null) {
            value = "";
        }
        return value;
    }

    /**
     * Setter for RA Name Generation Prefix
     * @param prefix RA name prefix
     *
     */ 
    public void setRANameGenPrefix(String prefix) {
        data.put(KEY_RA_NAMEGENERATIONPREFIX, prefix);
    }
    
    /**
     * Getter for RA Name Generation Postfix
     */     
    public String getRANameGenPostfix() {
        // Set default to empty String for aliases created before RA name generation was added.
        String value = (String) data.get(KEY_RA_NAMEGENERATIONPOSTFIX);
        if (value == null) {
            value = "";
        }
        return value;
    }

     /**
     * Setter for RA Name Generation Postfix.
     * @param postfix RA name postfix
     *
     */    
    public void setRANameGenPostfix(String postfix) {
        data.put(KEY_RA_NAMEGENERATIONPOSTFIX, postfix);
    }
    
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
    public LinkedList<AcmeExternalAccountBinding> getExternalAccountBinding() throws AccountBindingException {
        final LinkedList<AcmeExternalAccountBinding> result = new LinkedList<>();
        
        if (data.get(KEY_EXTERNAL_ACCOUNT_BINDING) instanceof List) {
            for (Object o : (List<?>) data.get(KEY_EXTERNAL_ACCOUNT_BINDING)) {
                if (o instanceof LinkedHashMap) {
                    final LinkedHashMap<Object,Object> eabData = (LinkedHashMap<Object,Object>) o;
                    final AcmeExternalAccountBinding eab = AcmeExternalAccountBindingFactory.INSTANCE.getArcheType((String) eabData.get("typeIdentifier"));
                    eab.setDataMap(eabData);
                    result.add(eab);
                } else {
                    log.error("Failed to read ACME EAB data. Invalid data type '" + o + "'.");
                    throw new AccountBindingException("Failed to read ACME EAB data. Invalid data type.");
                }
            }
        }
        return result;
    }

    public void setExternalAccountBinding(final LinkedList<AcmeExternalAccountBinding> eabs) {
        if (eabs != null) {
            final List<LinkedHashMap<Object,Object>> clones = new ArrayList<>();
            for (AcmeExternalAccountBinding eab : eabs) {
                final LinkedHashMap<Object,Object> clone = eab.clone().getDataMap();
                clones.add(clone);
            }
            data.put(KEY_EXTERNAL_ACCOUNT_BINDING, clones);
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

    /** 
     * For testing purposes only, the identifier can be set to 'localhost', if you want to issue certificates 
     * for arbitrary DNS names on your host -> http://localhost/.well-known/acme-challenge/{token}
     * 
     * @return the pattern we will use for "http-01" challenge validation. Defaults to example from RFC draft 06.
     * */
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
    
    public String getDnsIdentifiersChallengeTypes() {
        return (String) super.data.get(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES);
    }
    
    public List<String> getDnsIdentifiersChallengeTypesList() {
        final List<String> result = new ArrayList<>();
        final String types = getDnsIdentifiersChallengeTypes();
        if (types != null && types.length() > 0) {
            result.addAll(Arrays.asList(types.split(",")));
        }
        return result;
    }
    
    public void setDnsIdentifiersChallengeTypes(String types) throws Exception {
        if (types != null && !types.trim().isEmpty()) {
            // Remove duplicates.
            Set<String> challengeTypes = Stream.of(types.trim().split(",")).collect(Collectors.toSet());
            // Check value range.
            final List<String> availableChallengeTypes = AcmeChallenge.AcmeChallengeType.getDnsIdentifierChallengeTypes(AcmeIdentifier.AcmeIdentifierTypes.DNS);
            availableChallengeTypes.add(DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES);
            if (!availableChallengeTypes.containsAll(challengeTypes)) {
                throw new Exception("Invalid ACME DNS identifier challenge type. Use one of: " + availableChallengeTypes);
            }
            // Normalize selection any.
            if (challengeTypes.size() >= availableChallengeTypes.size() - 1) {
                challengeTypes = Collections.singleton(AcmeConfiguration.DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES);
            }
            super.data.put(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES, challengeTypes.stream().collect(Collectors.joining(",")));
        } else {
            super.data.put(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES, DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES);
        }
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
    
    public String getAuthorizedRedirectPorts() {
        return (String) super.data.get(KEY_AUTHORIZED_REDIRECT_PORTS);
    }
    
    public Set<Integer> getAuthorizedRedirectPortsList() {
        final String ports = getAuthorizedRedirectPorts();
        if (ports != null && !ports.trim().isEmpty()) {
            return Stream.of(ports.split(",")).map(Integer::parseInt).sorted().collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    public void setAuthorizedRedirectPorts(String ports) {
        if (ports != null && !ports.trim().isEmpty()) {
            ports = Stream.of(ports.trim().split(",")).map(Integer::parseInt).collect(Collectors.toSet())
                    .stream().sorted().map(i -> Integer.toString(i)).collect(Collectors.joining(","));
            super.data.put(KEY_AUTHORIZED_REDIRECT_PORTS, ports);
        } else {
            super.data.put(KEY_AUTHORIZED_REDIRECT_PORTS, "");
        }
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

    public int getApprovalForNewAccountId() {
        final Integer value = (Integer) data.get(KEY_APPROVAL_FOR_NEW_ACCOUNT_ID);
        return Objects.isNull(value) ? DEFAULT_APPROVAL_FOR_NEW_ACCOUNT_ID : value;
    }

    public void setApprovalForNewAccountId(int approvalForNewAccountId) {
        data.put(KEY_APPROVAL_FOR_NEW_ACCOUNT_ID, approvalForNewAccountId);
    }

    public int getApprovalForKeyChangeId() {
        final Integer value = (Integer) data.get(KEY_APPROVAL_FOR_KEY_CHANGE_ID);
        return Objects.isNull(value) ? DEFAULT_APPROVAL_FOR_KEY_CHANGE_ID : value;
    }

    public void setApprovalForKeyChangeId(int approvalForKeyChangeId) {
        data.put(KEY_APPROVAL_FOR_KEY_CHANGE_ID, approvalForKeyChangeId);
    }
    
    public boolean isApprovalForNewAccountRequired() {
        return DEFAULT_APPROVAL_FOR_NEW_ACCOUNT_ID != getApprovalForNewAccountId(); 
    }
    
    public boolean isApprovalForKeyChangeRequired() {
        return DEFAULT_APPROVAL_FOR_KEY_CHANGE_ID != getApprovalForKeyChangeId();
    }
    
    public boolean isClientAuthenticationRequired() {
        return Boolean.valueOf((String) super.data.get(KEY_CLIENT_AUTHENTICATION_REQUIRED));
    }
    
    public void setClientAuthenticationRequired(final boolean required) {
        super.data.put(KEY_CLIENT_AUTHENTICATION_REQUIRED, String.valueOf(required));
    }
    
    public String getPreferredRootCaSubjectDn() {
        String value = (String) data.get(KEY_PREFERRED_ROOT_CA_SUBJECTDN);
        if (StringUtils.isBlank(value)) {
            data.put(KEY_PREFERRED_ROOT_CA_SUBJECTDN, DEFAULT_PREFERRED_ROOT_CA_SUBJECTDN);
            return DEFAULT_PREFERRED_ROOT_CA_SUBJECTDN;
        } else {
            return value;
        }
    }
    
    public void setPreferredRootCaSubjectDn(String preferredRootCaSubjectDn) {
        data.put(KEY_PREFERRED_ROOT_CA_SUBJECTDN, preferredRootCaSubjectDn);
    }
    
    /** Initializes a new acme configuration with default values. */
    public void initialize(String alias) {
        alias += ".";
        setRANameGenScheme(DEFAULT_RA_USERNAME_GENERATION_SCHEME);
        setRANameGenParams(DEFAULT_RA_USERNAME_GENERATION_PARAMS);
        setRANameGenPrefix(DEFAULT_RA_USERNAME_GENERATION_PREFIX);
        setRANameGenPostfix(DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
        setEndEntityProfileId(DEFAULT_END_ENTITY_PROFILE_ID);
        setRequireExternalAccountBinding(DEFAULT_REQUIRE_EXTERNAL_ACCOUNT_BINDING);
//        try {
//            setExternalAccountBinding(Collections.singletonList(AcmeExternalAccountBindingFactory.INSTANCE.getDefaultImplementation()));
//        } catch (AccountBindingException e) {
//            // NOOP
//        }
        setPreAuthorizationAllowed(DEFAULT_PRE_AUTHORIZATION_ALLOWED);
        setTermsOfServiceUrl(DEFAULT_TERMS_OF_SERVICE_URL);
        setTermsOfServiceChangeUrl(DEFAULT_TERMS_OF_SERVICE_CHANGE_URL);
        setTermsOfServiceRequireNewApproval(DEFAULT_REQUIRE_NEW_APPROVAL);
        setAgreeToNewTermsOfServiceAllowed(DEFAULT_AGREE_TO_TERMS_OF_SERVICE_CHANGED);
        setWildcardCertificateIssuanceAllowed(DEFAULT_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED);
        setWildcardWithHttp01ChallengeAllowed(DEFAULT_KEY_WILDCARD_WITH_HTTP_01_CHALLENGE_ALLOWED);
        data.put(KEY_DNS_IDENTIFIER_CHALLENGE_TYPES, DEFAULT_DNS_IDENTIFIER_CHALLENGE_TYPES);
        setWebSiteUrl(DEFAULT_WEBSITE_URL);
        setOrderValidity(DEFAULT_ORDER_VALIDITY);
        setDnsResolver(DNS_RESOLVER_DEFAULT);
        setDnssecTrustAnchor(DnsSecDefaults.IANA_ROOT_ANCHORS_DEFAULT);
        setDnsPort(DNS_SERVER_PORT_DEFAULT);
        setUseDnsSecValidation(DEFAULT_USE_DNSSEC_VALIDATION);
        setAuthorizedRedirectPorts(DEFAULT_AUTHORIZED_REDIRECT_PORTS);
        setApprovalForNewAccountId(DEFAULT_APPROVAL_FOR_NEW_ACCOUNT_ID);
        setApprovalForKeyChangeId(DEFAULT_APPROVAL_FOR_KEY_CHANGE_ID);
        setClientAuthenticationRequired(DEFAULT_CLIENT_AUTHENTICATION_REQUIRED);
        setPreferredRootCaSubjectDn(DEFAULT_PREFERRED_ROOT_CA_SUBJECTDN);
    }
}
