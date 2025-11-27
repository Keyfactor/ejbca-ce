/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.base.Preconditions;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.scep.ScepEncryptionCertificateIssuanceException;
import org.ejbca.core.protocol.scep.ScepRaCertificateIssuer;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.util.SelectItemComparator;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.model.ListDataModel;
import jakarta.faces.model.SelectItem;
import jakarta.inject.Named;

/**
 * JavaServer Faces Managed Bean for managing SCEP configuration.
 */
@Named
@SessionScoped
public class ScepConfigMBean extends BaseManagedBean implements Serializable {

    private static final String HIDDEN_PWD = "**********";

    /**
     * Keep track of which token/key generated the encryption certificate, so if it changes
     * in the GUI we know to create a new one on save.  In CA mode, keep track of which CAs were selected, 
     * so if they change, we can generate new certificates for them.
     */
    public static class ScepRaCertificate implements Serializable {
        private static final long serialVersionUID = 1L;

        public ScepRaCertificate(Integer tokenId, String keyAlias, String pemEncodedCertificate) {
            this.tokenId = tokenId;
            this.keyAlias = keyAlias;
            this.pemEncodedCertificate = pemEncodedCertificate;
            this.caToPemEncodedCertificate = null;
        }

        public ScepRaCertificate(Integer tokenId, String keyAlias, HashMap<String, String> caToPemEncodedCertificate) {
            this.tokenId = tokenId;
            this.keyAlias = keyAlias;
            this.pemEncodedCertificate = null;
            this.caToPemEncodedCertificate = caToPemEncodedCertificate;
        }

        private Integer tokenId;
        private String keyAlias;
        private String pemEncodedCertificate;
        private HashMap<String, String> caToPemEncodedCertificate;
    };

    public class ScepAliasGuiInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private String alias;
        private String mode;
        private boolean includeCA;
        private boolean rootFirst;
        private boolean returnCaChainInGetCaCert;
        private boolean allowLegacyDigestAlgorithm;
        private String raCertProfile;
        private String raEEProfile;
        private String raAuthPassword;
        private String raDefaultCA;
        private String raNameGenScheme;
        private String raNameGenParameters;
        private String raNameGenPrefix;
        private String raNameGenPostfix;
        private boolean clientCertificateRenewal;
        private boolean allowClientCertificateRenewaWithOldKey;
        private boolean useIntune;
        private String intuneAuthority;
        private String intuneAadAppId;
        private boolean intuneAadUseKeyBinding;
        private String intuneAadAppKey;
        private String intuneAadAppKeyBinding;
        private String intuneTenant;
        private String intuneResourceUrl;
        private String intuneGraphApiVersion;
        private String intuneGraphResourceUrl;
        private String intuneProxyHost;
        private String intuneProxyPort;
        private String intuneProxyUser;
        private String intuneProxyPass;
        private Boolean useRaKeys = false;
        private Integer encryptionCryptoTokenId;
        private String encryptionKeyAlias;
        private ScepRaCertificate encryptionCertificateInfo;
        private String signingAlgorithm;
        private Integer signingCryptoTokenId;
        private String signingKeyAlias;
        private ScepRaCertificate signingCertificateInfo;
        private ArrayList<String> encryptionCAs;

        public ScepAliasGuiInfo(final String alias) {
            this.alias = alias;
            this.mode = (scepConfig.getRAMode(alias) ? ScepConfiguration.Mode.RA.getResource() : ScepConfiguration.Mode.CA.getResource());
            this.includeCA = scepConfig.getIncludeCA(alias);
            this.returnCaChainInGetCaCert = scepConfig.getReturnCaChainInGetCaCert(alias);
            this.rootFirst = scepConfig.getCaChainRootFirstOrder(alias);
            this.allowLegacyDigestAlgorithm = scepConfig.getAllowLegacyDigestAlgorithm(alias);
            this.raCertProfile = scepConfig.getRACertProfile(alias);
            this.raEEProfile = scepConfig.getRAEndEntityProfile(alias);
            this.raAuthPassword = ScepConfigMBean.HIDDEN_PWD;
            this.raDefaultCA = scepConfig.getRADefaultCA(alias);
            this.raNameGenScheme = scepConfig.getRANameGenerationScheme(alias);
            this.raNameGenParameters = scepConfig.getRANameGenerationParameters(alias);
            this.raNameGenPrefix = scepConfig.getRANameGenerationPrefix(alias);
            this.raNameGenPostfix = scepConfig.getRANameGenerationPostfix(alias);
            this.clientCertificateRenewal = scepConfig.getClientCertificateRenewal(alias);
            this.allowClientCertificateRenewaWithOldKey = scepConfig.getAllowClientCertificateRenewalWithOldKey(alias);
            this.setUseIntune(scepConfig.getUseIntune(alias));
            this.intuneAadUseKeyBinding = scepConfig.getIntuneAadUseKeyBinding(alias);
            this.intuneAadAppKeyBinding = scepConfig.getIntuneAadAppKeyBinding(alias);
            this.intuneAuthority = scepConfig.getIntuneAuthority(alias);
            this.intuneAadAppId = scepConfig.getIntuneAadAppId(alias);
            this.intuneAadAppKey = ScepConfigMBean.HIDDEN_PWD;
            this.intuneTenant = scepConfig.getIntuneTenant(alias);
            this.intuneResourceUrl = scepConfig.getIntuneResourceUrl(alias);
            this.intuneGraphApiVersion = scepConfig.getIntuneGraphApiVersion(alias);
            this.intuneGraphResourceUrl = scepConfig.getIntuneGraphResourceUrl(alias);
            this.intuneProxyHost = scepConfig.getIntuneProxyHost(alias);
            this.intuneProxyPort = scepConfig.getIntuneProxyPort(alias);
            this.intuneProxyUser = scepConfig.getIntuneProxyUser(alias);
            this.intuneProxyPass = ScepConfigMBean.HIDDEN_PWD;
            
            this.encryptionCertificateInfo = null;
            this.signingCertificateInfo = null;
            this.signingAlgorithm = scepConfig.getSigningAlgorithm(alias);
            this.signingKeyAlias = scepConfig.getSigningKeyAlias(alias);
            this.signingCryptoTokenId = scepConfig.getSigningCryptoTokenId(alias);
            this.encryptionKeyAlias = scepConfig.getEncryptionKeyAlias(alias);
            this.encryptionCryptoTokenId = scepConfig.getEncryptionCryptoTokenId(alias);

            // ra mode RA keys settings
            String pemEncryptionCertificate = scepConfig.getEncryptionCertificate(alias);
            if (pemEncryptionCertificate != null && isModeRa()) {
                this.encryptionCertificateInfo = new ScepRaCertificate(this.encryptionCryptoTokenId, this.encryptionKeyAlias, pemEncryptionCertificate);
            }
            String pemSigningCertificate = scepConfig.getSigningCertificate(alias);
            if (pemEncryptionCertificate != null && isModeRa()) {
                this.signingCertificateInfo = new ScepRaCertificate(signingCryptoTokenId, signingKeyAlias, pemSigningCertificate);
            }
            
            // CA mode RA keys settings
            var encryptionCertificates = scepConfig.getEncryptionCertificates(alias);
            if (encryptionCertificates != null && !isModeRa()) {
                this.encryptionCertificateInfo = new ScepRaCertificate(this.encryptionCryptoTokenId, this.encryptionKeyAlias, encryptionCertificates);
            }
            HashMap<String,String> signingCertificates = scepConfig.getSigningCertificates(alias);
            if (signingCertificates != null && !isModeRa()) {
                this.signingCertificateInfo = new ScepRaCertificate(this.signingCryptoTokenId, this.signingKeyAlias, signingCertificates);
            }
            
            this.encryptionCAs = scepConfig.getEncryptionCAs(alias);
            
            // one should be enough, but lets be paranoid
            this.useRaKeys = encryptionCryptoTokenId != null && encryptionKeyAlias != null && signingCryptoTokenId != null && signingKeyAlias != null;
        }

        public ScepAliasGuiInfo() {
            this.mode = ScepConfiguration.DEFAULT_OPERATION_MODE.toUpperCase();
            this.includeCA = Boolean.valueOf(ScepConfiguration.DEFAULT_INCLUDE_CA);
            this.rootFirst = Boolean.valueOf(ScepConfiguration.DEFAULT_CHAIN_ROOT_FIRST);
            this.returnCaChainInGetCaCert = Boolean.valueOf(ScepConfiguration.DEFAULT_RETURN_CA_CHAIN_IN_GETCACERT);
            this.allowLegacyDigestAlgorithm = Boolean.valueOf(ScepConfiguration.DEFAULT_ALLOW_LEGACY_DIGEST_ALGORITHM);
            this.raCertProfile = ScepConfiguration.DEFAULT_RA_CERTPROFILE;
            this.raEEProfile = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
            this.raAuthPassword = ScepConfiguration.DEFAULT_RA_AUTHPWD;
            this.raDefaultCA = ScepConfiguration.DEFAULT_RA_DEFAULTCA;
            this.raNameGenScheme = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_SCHEME;
            this.raNameGenParameters = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PARAMETERS;
            this.raNameGenPrefix = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PREFIX;
            this.raNameGenPostfix = ScepConfiguration.DEFAULT_RA_NAME_GENERATION_POSTFIX;
            this.clientCertificateRenewal = Boolean.valueOf(ScepConfiguration.DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
            this.allowClientCertificateRenewaWithOldKey = Boolean
                    .valueOf(ScepConfiguration.DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
            this.setUseIntune(false);
            this.intuneAuthority = "";
            this.intuneAadAppId = "";
            this.intuneAadAppKey = "";
            this.intuneAadAppKeyBinding = "";
            this.intuneAadUseKeyBinding = false;
            this.intuneTenant = "";
            this.intuneResourceUrl = "";
            this.intuneGraphApiVersion = "";
            this.intuneGraphResourceUrl = "";
            this.intuneProxyHost = "";
            this.intuneProxyPort = "";
            this.intuneProxyUser = "";
            this.intuneProxyPass = "";
            this.useRaKeys = false;
            this.encryptionCryptoTokenId = null;
            this.encryptionKeyAlias = null;
            this.encryptionCertificateInfo = null;
            this.signingAlgorithm = ScepConfiguration.DEFAULT_SIGNING_ALGORITHM;
            this.signingCryptoTokenId = null;
            this.signingKeyAlias = null;
            this.signingCertificateInfo = null;
            this.encryptionCAs = null;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public boolean isModeRa() {
            return ScepConfiguration.Mode.RA.getResource().equals(mode);
        }

        public boolean isModeCa() {
            return ScepConfiguration.Mode.CA.getResource().equals(mode);
        }

        public boolean isIncludeCA() {
            return includeCA;
        }

        public void setIncludeCA(boolean includeca) {
            this.includeCA = includeca;
        }

        public boolean isAllowLegacyDigestAlgorithm() {
            return allowLegacyDigestAlgorithm;
        }

        public void setAllowLegacyDigestAlgorithm(boolean allowLegacyDigestAlgorithm) {
            this.allowLegacyDigestAlgorithm = allowLegacyDigestAlgorithm;
        }

        public String getRaCertProfile() {
            return raCertProfile;
        }

        public void setRaCertProfile(String cp) {
            this.raCertProfile = cp;
        }

        public String getRaEEProfile() {
            return raEEProfile;
        }

        public void setRaEEProfile(String eep) {
            this.raEEProfile = eep;
        }

        public String getRaDefaultCA() {
            return raDefaultCA;
        }

        public void setRaDefaultCA(String caname) {
            this.raDefaultCA = caname;
        }

        public String getRaAuthPassword() {
            return this.raAuthPassword;
        }

        public void setRaAuthPassword(String raAuthPwd) {
            this.raAuthPassword = raAuthPwd;
        }

        public String getRaNameGenScheme() {
            return raNameGenScheme;
        }

        public void setRaNameGenScheme(String scheme) {
            this.raNameGenScheme = scheme;
        }

        public boolean isRaNameGenSchemeFixed() {
            return "FIXED".equals(raNameGenScheme);
        }

        public boolean isRaNameGenSchemeDn() {
            return "DN".equals(raNameGenScheme);
        }

        public String getRaNameGenParams() {
            return raNameGenParameters;
        }

        public void setRaNameGenParams(String params) {
            this.raNameGenParameters = params;
        }

        public String getRaNameGenPrefix() {
            return raNameGenPrefix;
        }

        public void setRaNameGenPrefix(String prefix) {
            this.raNameGenPrefix = prefix;
        }

        public String getRaNameGenPostfix() {
            return raNameGenPostfix;
        }

        public void setRaNameGenPostfix(String postfix) {
            this.raNameGenPostfix = postfix;
        }

        public boolean getClientCertificateRenewal() {
            return this.clientCertificateRenewal;
        }

        public void setClientCertificateRenewal(boolean clientCertificateRenewal) {
            this.clientCertificateRenewal = clientCertificateRenewal;
        }

        public boolean getAllowClientCertificateRenewaWithOldKey() {
            return this.allowClientCertificateRenewaWithOldKey;
        }

        public void setAllowClientCertificateRenewaWithOldKey(boolean allowClientCertificateRenewaWithOldKey) {
            this.allowClientCertificateRenewaWithOldKey = allowClientCertificateRenewaWithOldKey;
        }

        public boolean isUseIntune() {
            return useIntune;
        }

        public void setUseIntune(boolean useIntune) {
            this.useIntune = useIntune;
        }

        public String getIntuneAuthority() {
            return intuneAuthority;
        }

        public void setIntuneAuthority(String intuneAuthority) {
            this.intuneAuthority = intuneAuthority;
        }

        public String getIntuneAadAppId() {
            return intuneAadAppId;
        }

        public void setIntuneAadAppId(String intuneAadAppId) {
            this.intuneAadAppId = intuneAadAppId;
        }

        public String getIntuneAadAppKey() {
            return intuneAadAppKey;
        }

        public void setIntuneAadAppKey(String intuneAadAppKey) {
            this.intuneAadAppKey = intuneAadAppKey;
        }

        public String getIntuneTenant() {
            return intuneTenant;
        }

        public void setIntuneTenant(String intuneTenant) {
            this.intuneTenant = intuneTenant;
        }

        public String getIntuneResourceUrl() {
            return intuneResourceUrl;
        }

        public void setIntuneResourceUrl(String intuneResourceUrl) {
            this.intuneResourceUrl = intuneResourceUrl;
        }

        public String getIntuneGraphApiVersion() {
            return intuneGraphApiVersion;
        }

        public void setIntuneGraphApiVersion(String intuneGraphApiVersion) {
            this.intuneGraphApiVersion = intuneGraphApiVersion;
        }

        public String getIntuneGraphResourceUrl() {
            return intuneGraphResourceUrl;
        }

        public void setIntuneGraphResourceUrl(String intuneGraphResourceUrl) {
            this.intuneGraphResourceUrl = intuneGraphResourceUrl;
        }

        public String getIntuneProxyHost() {
            return intuneProxyHost;
        }

        public void setIntuneProxyHost(String intuneProxyHost) {
            this.intuneProxyHost = intuneProxyHost;
        }

        public String getIntuneProxyPort() {
            return intuneProxyPort;
        }

        public void setIntuneProxyPort(String intuneProxyPort) {
            this.intuneProxyPort = intuneProxyPort;
        }

        public String getIntuneProxyUser() {
            return intuneProxyUser;
        }

        public void setIntuneProxyUser(String intuneProxyUser) {
            this.intuneProxyUser = intuneProxyUser;
        }

        public String getIntuneProxyPass() {
            return intuneProxyPass;
        }

        public void setIntuneProxyPass(String intuneProxyPass) {
            this.intuneProxyPass = intuneProxyPass;
        }

        public String getIntuneAadAppKeyBinding() {
            return intuneAadAppKeyBinding;
        }

        public void setIntuneAadAppKeyBinding(String intuneAadKeyBinding) {
            this.intuneAadAppKeyBinding = intuneAadKeyBinding;
        }

        public boolean isIntuneAadUseKeyBinding() {
            return intuneAadUseKeyBinding;
        }

        public void setIntuneAadUseKeyBinding(boolean intuneAadUseKeyBinding) {
            this.intuneAadUseKeyBinding = intuneAadUseKeyBinding;
        }

        public boolean isReturnCaChainInGetCaCert() {
            return returnCaChainInGetCaCert;
        }

        public void setReturnCaChainInGetCaCert(boolean returnCaChainInGetCaCert) {
            this.returnCaChainInGetCaCert = returnCaChainInGetCaCert;
        }

        public boolean isRootFirst() {
            return rootFirst;
        }

        public void setRootFirst(boolean rootFirst) {
            this.rootFirst = rootFirst;
        }

        public Integer getEncryptionCryptoTokenId() {
            return encryptionCryptoTokenId;
        }

        public void setEncryptionCryptoTokenId(Integer cryptotokenId) {
            this.encryptionCryptoTokenId = cryptotokenId;
            if (cryptotokenId == null) {
                encryptionKeyAlias = null;
            } else {
                // token has changed - choose the first 
                var availableKeyAliases = getAvailableKeyAliases(encryptionCryptoTokenId, "RSA");
                if (availableKeyAliases.size() > 0) {
                    encryptionKeyAlias = availableKeyAliases.get(0);
                } else {
                    encryptionKeyAlias = null;
                }
            }
        }

        public String getEncryptionKeyAlias() {
            return encryptionKeyAlias;
        }

        public void setEncryptionKeyAlias(String encryptionKeyAlias) {
            this.encryptionKeyAlias = encryptionKeyAlias;
        }

        public ScepRaCertificate getEncryptionCertificate() {
            return encryptionCertificateInfo;
        }

        public ScepRaCertificate getSigningCertificate() {
            return signingCertificateInfo;
        }


        public void setEncryptionCertificate(ScepRaCertificate encryptionCertificate) {
            this.encryptionCertificateInfo = encryptionCertificate;
        }

        /**
         * is this scep profile using a separate encryption key and no certificate has been issued for it?
         */
        public boolean encryptionCertificateMustBeGenerated() {
            if (!getUseRaKeys()) {
                return false;
            }
            
            return (encryptionCryptoTokenId != null && encryptionKeyAlias != null
                    && (encryptionCertificateInfo == null || encryptionCertificateInfo.pemEncodedCertificate == null
                            || !encryptionCertificateInfo.tokenId.equals(encryptionCryptoTokenId) || !encryptionCertificateInfo.keyAlias.equals(encryptionKeyAlias)));
        }

        /**
         * is this scep profile using a separate encryption key and no certificate has been issued for it?
         */
        public boolean signingCertificateMustBeGenerated() {
            if (!getUseRaKeys()) {
                return false;
            }

            return (signingCryptoTokenId != null && signingKeyAlias != null
                    && (signingCertificateInfo == null || signingCertificateInfo.pemEncodedCertificate == null
                            || !signingCertificateInfo.tokenId.equals(signingCryptoTokenId) || !signingCertificateInfo.keyAlias.equals(signingKeyAlias)));
        }

        /**
         * is this scep profile using a separate encryption key and no certificate has been issued for it?
         */
        public Set<String> casThatAlreadyHaveEncryptionCerts() {
            Preconditions.checkState(!currentAliasIsRAMode(), "casThatNeedEncryptionCerts called when in RA mode");
            if (!getUseRaKeys()) {
                return new HashSet<>();
            }
            
            // no key selected, so no already generated certs
            else if (encryptionCryptoTokenId == null && encryptionKeyAlias == null) {
                return new HashSet<>();
            }
            
            // no previously generated encryption certificates 
            else if (encryptionCertificateInfo == null) {
                return new HashSet<>();
            }
            
            // key changed - none of our certs are valid anymore
            else if (!encryptionCertificateInfo.tokenId.equals(encryptionCryptoTokenId) || !encryptionCertificateInfo.keyAlias.equals(encryptionKeyAlias)) {
                return new HashSet<>();
            }
            
            // key is the same, return the CAs we already have certs for
            else {
                return this.encryptionCertificateInfo.caToPemEncodedCertificate.keySet();
            }
        }

        /**
         * is this scep profile using a separate encryption key and no certificate has been issued for it?
         */
        public Set<String> casThatAlreadyHaveSigningCerts() {
            Preconditions.checkState(!currentAliasIsRAMode(), "casThatAlreadyHaveSigningCerts called when in RA mode");
            if (!getUseRaKeys()) {
                return new HashSet<>();
            }
            
            // no key selected, so no previously generated certs
            else if (signingCryptoTokenId == null && signingKeyAlias == null) {
                return new HashSet<>();
            }
            
            // no previously generated encryption certificates 
            else if (signingCertificateInfo == null) {
                return new HashSet<>();
            }
            
            // key changed - none of our certs are valid anymore
            if (!signingCertificateInfo.tokenId.equals(signingCryptoTokenId) || !signingCertificateInfo.keyAlias.equals(signingKeyAlias)) {
                return new HashSet<>();
            }
            
            // key is the same, return the CAs we already have certs for
            else {
                return this.signingCertificateInfo.caToPemEncodedCertificate.keySet();
            }
        }


        public void setEncryptionCertificate(Integer cryptoToken, String encryptionKeyAlias, X509Certificate encryptionCertificate) {
            String pemEncodedCertificate;
            try {
                pemEncodedCertificate = CertTools.getPemFromCertificate(encryptionCertificate);
            } catch (CertificateEncodingException e) {
                // this should never happen
                log.error("Unexpected certificate encoding exception", e);
                throw new RuntimeException("Can never happen exception", e);
            }

            this.encryptionCertificateInfo = new ScepRaCertificate(cryptoToken, encryptionKeyAlias, pemEncodedCertificate);
        }

        public void setSigningCertificate(Integer cryptoToken, String signingKeyAlias, X509Certificate signingCertificate) {
            String pemEncodedCertificate;
            try {
                pemEncodedCertificate = CertTools.getPemFromCertificate(signingCertificate);
            } catch (CertificateEncodingException e) {
                // this should never happen
                log.error("Unexpected certificate encoding exception", e);
                throw new RuntimeException("Can never happen exception", e);
            }

            this.signingCertificateInfo = new ScepRaCertificate(cryptoToken, signingKeyAlias, pemEncodedCertificate);
        }

        public Boolean getUseRaKeys() {
            return useRaKeys;
        }

        public void setUseRaKeys(Boolean useRaKeys) {
            this.useRaKeys = useRaKeys;
            
            if (!useRaKeys) {
                encryptionCryptoTokenId = null;
                encryptionKeyAlias = null;
                signingAlgorithm = null;
                signingCryptoTokenId = null;
                signingKeyAlias = null;
            } else {
                signingAlgorithm = ScepConfiguration.DEFAULT_SIGNING_ALGORITHM;
                // pick the first entries as defaults
                if (encryptionCryptoTokenId == null) {
                    ArrayList<Pair<Integer,String>> availableTokens = getAvailableTokens();
                    if (availableTokens.size() > 0) {
                        encryptionCryptoTokenId = availableTokens.get(0).getKey();
                        var availableKeyAliases = getAvailableKeyAliases(encryptionCryptoTokenId, "RSA");
                        if (availableKeyAliases.size() > 0) {
                            encryptionKeyAlias = availableKeyAliases.get(0);
                        }
                    }
                }
    
                // pick the first entries as defaults
                if (signingCryptoTokenId == null) {
                    ArrayList<Pair<Integer,String>> availableTokens = getAvailableTokens();
                    if (availableTokens.size() > 0) {
                        signingCryptoTokenId = availableTokens.get(0).getKey();
                        var availableKeyAliases = getAvailableKeyAliases(signingCryptoTokenId,
                                AlgorithmTools.getKeyAlgorithmFromSigAlg(signingAlgorithm));
                        if (availableKeyAliases.size() > 0) {
                            signingKeyAlias = availableKeyAliases.get(0);
                        }
                    }
                }
            }
        }

        public String getSigningAlgorithm() {
            return signingAlgorithm;
        }

        public void setSigningAlgorithm(final String sigalg) {
            this.signingAlgorithm = sigalg;
        }

        public String getSigningKeyAlias() {
            return signingKeyAlias;
        }

        public void setSigningKeyAlias(String signingKeyAlias) {
            this.signingKeyAlias = signingKeyAlias;
        }

        public Integer getSigningCryptoTokenId() {
            return signingCryptoTokenId;
        }

        public void setSigningCryptoTokenId(Integer signingCryptoTokenId) {
            this.signingCryptoTokenId = signingCryptoTokenId;
            if (signingCryptoTokenId == null) {
                signingKeyAlias = null;
            } else {
                // token has changed, so the old alias may no longer be valid
                var availableKeyAliases = getAvailableKeyAliases(signingCryptoTokenId, AlgorithmTools.getKeyAlgorithmFromSigAlg(signingAlgorithm));
                if (availableKeyAliases.size() > 0) {
                    signingKeyAlias = availableKeyAliases.get(0);
                } else {
                    signingKeyAlias = null;
                }
            }
        }
        
        public Collection<String> getEncryptionCAs() {
            if (encryptionCAs == null) {
                return new ArrayList<>();
            } else {
                return encryptionCAs;
            }
        }

        public void setEncryptionCAs(final Collection<String> cas) {
            encryptionCAs = new ArrayList<>();
            encryptionCAs.addAll(cas);
        }

        public void setEncryptionCertificates(Integer tokenId, String keyAlias, HashMap<String, String> caToCertificate) {
            this.encryptionCertificateInfo = new ScepRaCertificate(tokenId, keyAlias, caToCertificate);
        }

        public void setSigningCertificates(Integer tokenId, String keyAlias, HashMap<String, String> caToCertificate) {
            this.signingCertificateInfo = new ScepRaCertificate(tokenId, keyAlias, caToCertificate);
        }
    }

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;

    private static final long serialVersionUID = 2L;
    private static final Logger log = Logger.getLogger(ScepConfigMBean.class);
    private ScepAliasGuiInfo currentAlias = null;
    private String selectedAlias;
    private ScepConfiguration scepConfig;
    private boolean currentAliasEditMode = false;
    private final GlobalConfigurationSessionLocal globalConfigSession = getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    private final AuthenticationToken authenticationToken = getAdmin();
    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final CertificateProfileSessionLocal certProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final EndEntityProfileSessionLocal endentityProfileSession = getEjbcaWebBean().getEjb().getEndEntityProfileSession();
    private final EnterpriseEditionEjbBridgeSessionLocal editionEjbBridgeSession = (EnterpriseEditionEjbBridgeSessionLocal) getEjbcaWebBean().getEnterpriseEjb();

    public ScepConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
    }

    /**
     * Force reload from underlying (cache) layer for the current SCEP configuration alias
     */
    private void flushCache() {
        currentAlias = null;
        currentAliasEditMode = false;
        scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
    }

    public String getSelectedAlias() {
        return selectedAlias;
    }

    public void setSelectedAlias(String alias) {
        selectedAlias = alias;
    }

    public boolean isCurrentAliasEditMode() {
        return currentAliasEditMode;
    }

    public boolean isAllowedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    public void setCurrentAliasEditMode(boolean currentAliasEditMode) {
        this.currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
    }

    /**
     * Build a list sorted by name from the existing SCEP configuration aliases
     */
    public ListDataModel<ScepAliasGuiInfo> getAliasGuiList() {
        flushCache();
        return new ListDataModel<>(
                scepConfig.getAliasList()
                        .stream()
                        .sorted(String::compareToIgnoreCase)
                        .map(ScepAliasGuiInfo::new)
                        .collect(Collectors.toList())
        );
    }

    public boolean isAliasListEmpty(){
        return scepConfig.getAliasList().isEmpty();
    }

    public ScepAliasGuiInfo getCurrentAlias() {
        if (this.currentAlias == null && selectedAlias != null && scepConfig.aliasExists(selectedAlias)) {
            this.currentAlias = new ScepAliasGuiInfo(selectedAlias);
        }
        return this.currentAlias;
    }

    protected boolean renameOrAddAlias() {

        String oldAlias = selectedAlias;
        String newAlias = currentAlias.getAlias();

        if (StringUtils.isNotEmpty(oldAlias) && Objects.equals(oldAlias, newAlias)) {
            return true;
        }

        if (StringUtils.isEmpty(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        }

        if (!StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        }

        if (scepConfig.aliasExists(newAlias)) {
            addErrorMessage("SCEP_ALIAS_ALREADY_EXISTS");
            return false;
        }

        if(StringUtils.isEmpty(oldAlias)){
            scepConfig.addAlias(newAlias);
        }else {
            scepConfig.renameAlias(oldAlias, newAlias);
        }

        selectedAlias = currentAlias.getAlias();
        return true;
    }

    public String saveCurrentAlias() {
        if (currentAlias != null) {

            if (!renameOrAddAlias()) {
                return null;
            }

            String alias = currentAlias.getAlias();
            scepConfig.setRAMode(alias, currentAliasIsRAMode());
            scepConfig.setIncludeCA(alias, currentAlias.isIncludeCA());
            scepConfig.setReturnCaChainInGetCaCert(alias, currentAlias.isReturnCaChainInGetCaCert());
            scepConfig.setCaChainRootFirstOrder(alias, currentAlias.isRootFirst());
            scepConfig.setAllowLegacyDigestAlgorithm(alias, currentAlias.allowLegacyDigestAlgorithm);
            scepConfig.setRACertProfile(alias, currentAlias.getRaCertProfile());
            scepConfig.setRAEndEntityProfile(alias, currentAlias.getRaEEProfile());
            scepConfig.setRADefaultCA(alias, currentAlias.getRaDefaultCA());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getRaAuthPassword().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setRAAuthpassword(alias, currentAlias.getRaAuthPassword());
            }
            scepConfig.setRANameGenerationScheme(alias, currentAlias.getRaNameGenScheme());
            scepConfig.setRANameGenerationParameters(alias, currentAlias.getRaNameGenParams());
            scepConfig.setRANameGenerationPrefix(alias, currentAlias.getRaNameGenPrefix());
            scepConfig.setRANameGenerationPostfix(alias, currentAlias.getRaNameGenPostfix());
            if ("ra".equalsIgnoreCase(currentAlias.getMode())) {
                scepConfig.setClientCertificateRenewal(alias, false);
                scepConfig.setAllowClientCertificateRenewalWithOldKey(alias, false);
            } else {
                scepConfig.setClientCertificateRenewal(alias, currentAlias.getClientCertificateRenewal());
                scepConfig.setAllowClientCertificateRenewalWithOldKey(alias, currentAlias.getAllowClientCertificateRenewaWithOldKey());
            }
            scepConfig.setUseIntune(alias, currentAlias.isUseIntune());
            scepConfig.setIntuneAuthority(alias, currentAlias.getIntuneAuthority());
            scepConfig.setIntuneAadAppId(alias, currentAlias.getIntuneAadAppId());
            scepConfig.setIntuneAadUseKeyBinding(alias, currentAlias.isIntuneAadUseKeyBinding());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getIntuneAadAppKey().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setIntuneAadAppKey(alias, currentAlias.getIntuneAadAppKey());
            }
            scepConfig.setIntuneAadAppKeyBinding(alias, currentAlias.getIntuneAadAppKeyBinding());
            scepConfig.setIntuneTenant(alias, currentAlias.getIntuneTenant());
            scepConfig.setIntuneResourceUrl(alias, currentAlias.getIntuneResourceUrl());
            scepConfig.setIntuneGraphApiVersion(alias, currentAlias.getIntuneGraphApiVersion());
            scepConfig.setIntuneGraphResourceUrl(alias, currentAlias.getIntuneGraphResourceUrl());
            scepConfig.setIntuneProxyHost(alias, currentAlias.getIntuneProxyHost());
            scepConfig.setIntuneProxyPort(alias, currentAlias.getIntuneProxyPort());
            scepConfig.setIntuneProxyUser(alias, currentAlias.getIntuneProxyUser());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!currentAlias.getIntuneProxyPass().equals(ScepConfigMBean.HIDDEN_PWD)) {
                scepConfig.setIntuneProxyPass(alias, currentAlias.getIntuneProxyPass());
            }

            try {
                // if we're using RA keys, make sure all key and tokens have selections, and issue any needed certificates
                if (!currentAlias.useRaKeys) {
                    scepConfig.setEncryptionCertificate(alias, null);
                    scepConfig.setEncryptionCertificates(alias, null);
                    scepConfig.setEncryptionCryptoTokenId(alias, null);
                    scepConfig.setEncryptionKeyAlias(alias, null);
                    scepConfig.setSigningAlgorithm(alias, null);
                    scepConfig.setSigningCertificate(alias, null);
                    scepConfig.setSigningCertificates(alias, null);
                    scepConfig.setSigningCryptoTokenId(alias, null);
                    scepConfig.setSigningKeyAlias(alias, null);
                    scepConfig.setEncryptionCAs(alias, null);
                } else if (currentAliasIsRAMode()) {
                    if (currentAlias.encryptionCryptoTokenId == null || currentAlias.encryptionKeyAlias == null
                            || currentAlias.signingCryptoTokenId == null || currentAlias.signingKeyAlias == null
                            || currentAlias.signingAlgorithm == null) {
                        log.debug("User attempted to save SCEP configuration using RA keys without choosing keys");
                        addErrorMessage("SELECTRAKEYS");
                        return null;
                    }
                    
                    // if a new encryption/signing certificates need to be issued for this SCEP profile, issue them and set them in the config
                    var issuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession, endEntityManagementSession,
                            certificateCreateSession);
                    if (currentAlias.encryptionCertificateMustBeGenerated()) {
                        var certificate = issuer.issueEncryptionCertificate(authenticationToken, currentAlias.getRaDefaultCA(),
                                currentAlias.encryptionCryptoTokenId, currentAlias.encryptionKeyAlias);
                        currentAlias.setEncryptionCertificate(currentAlias.encryptionCryptoTokenId, currentAlias.encryptionKeyAlias, certificate);
                    }
                    if (currentAlias.signingCertificateMustBeGenerated()) {
                        var certificate = issuer.issueSigningCertificate(authenticationToken, currentAlias.getRaDefaultCA(),
                                currentAlias.signingCryptoTokenId, currentAlias.signingKeyAlias);
                        currentAlias.setSigningCertificate(currentAlias.signingCryptoTokenId, currentAlias.signingKeyAlias, certificate);
                    }
                    
                    // save SCEP RA certificate settings
                    scepConfig.setEncryptionCryptoTokenId(alias, currentAlias.encryptionCryptoTokenId);
                    scepConfig.setEncryptionKeyAlias(alias, currentAlias.encryptionKeyAlias);
                    if (currentAlias.encryptionCryptoTokenId == null || currentAlias.encryptionCertificateInfo == null) {
                        scepConfig.setEncryptionCertificate(alias, null);
                    } else {
                        scepConfig.setEncryptionCertificate(alias, currentAlias.encryptionCertificateInfo.pemEncodedCertificate);
                    }
                    scepConfig.setSigningAlgorithm(alias, currentAlias.signingAlgorithm);
                    scepConfig.setSigningCryptoTokenId(alias, currentAlias.signingCryptoTokenId);
                    scepConfig.setSigningKeyAlias(alias, currentAlias.signingKeyAlias);
                    if (currentAlias.signingCryptoTokenId == null || currentAlias.signingCertificateInfo == null) {
                        scepConfig.setSigningCertificate(alias, null);
                    } else {
                        scepConfig.setSigningCertificate(alias, currentAlias.signingCertificateInfo.pemEncodedCertificate);
                    }
                } else {
                    // CA mode
                    if (currentAlias.encryptionCryptoTokenId == null || currentAlias.encryptionKeyAlias == null
                            || currentAlias.signingCryptoTokenId == null || currentAlias.signingKeyAlias == null
                            || currentAlias.signingAlgorithm == null) {
                        log.debug("User attempted to save SCEP configuration using RA keys without choosing keys");
                        addErrorMessage("SELECTRAKEYS");
                        return null;
                    }
                    else if (currentAlias.encryptionCAs.isEmpty()) {
                        log.debug("User attempted to save SCEP configuration using RA keys without choosing a CA");
                        addErrorMessage("SCEP_SELECT_AVAILABLE_CA");
                        return null;
                    }
                    
                    // if a new encryption/signing certificates need to be issued for this SCEP profile, issue them and set them in the config
                    var issuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession, endEntityManagementSession,
                            certificateCreateSession);

                    // issue any new scep encryption certificates
                    HashMap<String, String> caToEncryptionCertificate = new HashMap<>();
                    for (var caName : currentAlias.encryptionCAs) {
                        if (!currentAlias.casThatAlreadyHaveEncryptionCerts().contains(caName)) {
                            var certificate = issuer.issueEncryptionCertificate(authenticationToken, caName, currentAlias.encryptionCryptoTokenId, currentAlias.encryptionKeyAlias);
                            var pemEncodedCertificate = CertTools.getPemFromCertificate(certificate);
                            caToEncryptionCertificate.put(caName, pemEncodedCertificate);
                        } 
                        else {
                            caToEncryptionCertificate.put(caName, currentAlias.encryptionCertificateInfo.caToPemEncodedCertificate.get(caName));
                        }
                    }
                    currentAlias.setEncryptionCertificates(currentAlias.encryptionCryptoTokenId, currentAlias.encryptionKeyAlias, caToEncryptionCertificate);

                    // issue any new scep signing certificates
                    HashMap<String, String> caToSigningCertificate = new HashMap<>();
                    for (var caName : currentAlias.encryptionCAs) {
                        if (!currentAlias.casThatAlreadyHaveSigningCerts().contains(caName)) {
                            var certificate = issuer.issueSigningCertificate(authenticationToken, caName, currentAlias.signingCryptoTokenId, currentAlias.signingKeyAlias);
                            var pemEncodedCertificate = CertTools.getPemFromCertificate(certificate);
                            caToSigningCertificate.put(caName, pemEncodedCertificate);
                        } 
                        else {
                            caToSigningCertificate.put(caName, currentAlias.signingCertificateInfo.caToPemEncodedCertificate.get(caName));
                        }
                    }
                    currentAlias.setSigningCertificates(currentAlias.signingCryptoTokenId, currentAlias.signingKeyAlias, caToSigningCertificate);

                    // save SCEP RA certificate settings
                    scepConfig.setEncryptionCryptoTokenId(alias, currentAlias.encryptionCryptoTokenId);
                    scepConfig.setEncryptionKeyAlias(alias, currentAlias.encryptionKeyAlias);
                    if (currentAlias.encryptionCryptoTokenId == null || currentAlias.encryptionCertificateInfo == null) {
                        scepConfig.setEncryptionCertificates(alias, null);
                    } else {
                        scepConfig.setEncryptionCertificates(alias, caToEncryptionCertificate);
                    }
                    scepConfig.setSigningAlgorithm(alias, currentAlias.signingAlgorithm);
                    scepConfig.setSigningCryptoTokenId(alias, currentAlias.signingCryptoTokenId);
                    scepConfig.setSigningKeyAlias(alias, currentAlias.signingKeyAlias);
                    if (currentAlias.signingCryptoTokenId == null || currentAlias.signingCertificateInfo == null) {
                        scepConfig.setSigningCertificates(alias, null);
                    } else {
                        scepConfig.setSigningCertificates(alias, caToSigningCertificate);
                    }
                    
                    scepConfig.setEncryptionCAs(alias, currentAlias.getEncryptionCAs());
                }

                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Cannot save alias. Administrator is not authorized.";
                log.info(msg + e.getLocalizedMessage());
                super.addNonTranslatedErrorMessage(msg);
            } catch (ScepEncryptionCertificateIssuanceException e) {
                String msg = "Cannot save alias. Unable to issue an RA certificate.";
                log.info(msg + e.getLocalizedMessage(), e);
                addErrorMessage("CANTISSUERACERT", e.getLocalizedMessage());
                return null;
            } catch (CertificateEncodingException e) {
                // realistically, this can't happen
                String msg = "Cannot save alias. Unable to encode certificate to PEM.";
                log.info(msg + e.getLocalizedMessage(), e);
                super.addNonTranslatedErrorMessage(msg);
                return null;
            }
        }
        flushCache();
        return "done";
    }

    private boolean currentAliasIsRAMode() {
        return "ra".equalsIgnoreCase(currentAlias.getMode());
    }

    public String deleteAlias() {
        if (scepConfig.aliasExists(selectedAlias)) {
            scepConfig.removeAlias(selectedAlias);
            try {
                globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
            } catch (AuthorizationDeniedException e) {
                String msg = "Failed to remove alias: " + e.getLocalizedMessage();
                log.info(msg, e);
                super.addNonTranslatedErrorMessage(msg);
            }
        } else {
            String msg = "Cannot remove alias. It does not exist.";
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
        flushCache();
        return "done";
    }

    public String addAliasAction() {
        selectedAlias = null;
        currentAlias = new ScepAliasGuiInfo();
        currentAliasEditMode = true;
        return "edit";
    }

    public String editAliasAction(String alias) {
        selectedAlias = alias;
        currentAlias = new ScepAliasGuiInfo(alias);
        currentAliasEditMode = true;
        return "edit";
    }

    public String viewAliasAction(String alias) {
        selectedAlias = alias;
        currentAlias = null;
        currentAliasEditMode = false;
        return "edit";
    }

    public String deleteAliasAction(String alias) {
        selectedAlias = alias;
        return "delete";
    }

    /**
     * Invoked when admin cancels a SCEP alias create or edit.
     */
    public String cancelCurrentAlias() {
        flushCache();
        return "cancel";
    }

    /**
     * @return a list of usable operational modes
     */
    public List<SelectItem> getAvailableModes() {
        return List.of(
                new SelectItem(ScepConfiguration.Mode.RA.getResource()),
                new SelectItem(ScepConfiguration.Mode.CA.getResource())
        );
    }

    /** @return a list of usable operational modes */
    public List<SelectItem> getChainOrderOptions() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(true, "Root First"));
        ret.add(new SelectItem(false, "Root Last"));
        return ret;
    }

    /**
     * @return a list of all CA names
     */
    public List<SelectItem> getAvailableCAs() {
        final Collection<String> cas = caSession.getAuthorizedCaNames(authenticationToken);
        return cas.stream()
                .map(SelectItem::new)
                .sorted(new SelectItemComparator())
                .collect(Collectors.toList());
    }

    /**
     * @return a list of EndEntity profiles that this admin is authorized to
     */
    public List<SelectItem> getAuthorizedEEProfileNames() {
        final Collection<Integer> endEntityProfileIds = endentityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        final Map<Integer, String> nameMap = endentityProfileSession.getEndEntityProfileIdToNameMap();
        return endEntityProfileIds.stream()
                .map(nameMap::get)
                .map(SelectItem::new)
                .sorted(new SelectItemComparator())
                .collect(Collectors.toList());
    }

    /**
     * @return a list of certificate profiles that are available for the current end entity profile
     */
    public List<SelectItem> getAvailableCertProfilesOfEEProfile() {
        String eep = currentAlias.getRaEEProfile();
        if (StringUtils.isEmpty(eep)) {
            eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
        }
        final EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);
        if (p != null) {
            return p.getAvailableCertificateProfileIds().stream()
                    .map(certProfileSession::getCertificateProfileName)
                    .map(SelectItem::new)
                    .sorted(new SelectItemComparator())
                    .collect(Collectors.toList());
        }
        return List.of();
    }

    /**
     * @return a list of CAs that are available for the current end entity profile
     */
    public List<SelectItem> getAvailableCAsOfEEProfile() {
        String eep = currentAlias.getRaEEProfile();
        if (StringUtils.isEmpty(eep)) {
            eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
        }
        final EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);
        if (p != null) {
            if (p.getAvailableCAs().contains(CAConstants.ALLCAS)) {
                return getAvailableCAs();
            } else {
                final Map<Integer, String> caidname = caSession.getCAIdToNameMap();
                return p.getAvailableCAs().stream()
                        .map(caidname::get)
                        .map(SelectItem::new)
                        .sorted(new SelectItemComparator())
                        .collect(Collectors.toList());
            }
        }
        return List.of();
    }

    public List<SelectItem> getAvailableSchemes() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("DN", "DN Part"));
        ret.add(new SelectItem("RANDOM", "RANDOM (Generates a 12 characters long random username)"));
        ret.add(new SelectItem("FIXED", "FIXED"));
        ret.add(new SelectItem("USERNAME", "Use entire request DN as username"));
        return ret;
    }

    public List<SelectItem> getDnParts() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("CN", "CN"));
        ret.add(new SelectItem("UID", "UID"));
        ret.add(new SelectItem("OU", "OU"));
        ret.add(new SelectItem("O", "O"));
        ret.add(new SelectItem("L", "L"));
        ret.add(new SelectItem("ST", "ST"));
        ret.add(new SelectItem("DC", "DC"));
        ret.add(new SelectItem("C", "C"));
        ret.add(new SelectItem("emailAddress", "emailAddress"));
        ret.add(new SelectItem("SN", "serialNumber"));
        ret.add(new SelectItem("givenName", "givenName"));
        ret.add(new SelectItem("initials", "initials"));
        ret.add(new SelectItem("surname", "surname"));
        ret.add(new SelectItem("title", "title"));
        ret.add(new SelectItem("unstructuredAddress", "unstructuredAddress"));
        ret.add(new SelectItem("unstructuredName", "unstructuredName"));
        ret.add(new SelectItem("postalCode", "postalCode"));
        ret.add(new SelectItem("businessCategory", "businessCategory"));
        ret.add(new SelectItem("dnQualifier", "dnQualifier"));
        ret.add(new SelectItem("postalAddress", "postalAddress"));
        ret.add(new SelectItem("telephoneNumber", "telephoneNumber"));
        ret.add(new SelectItem("pseudonym", "pseudonym"));
        ret.add(new SelectItem("streetAddress", "streetAddress"));
        ret.add(new SelectItem("name", "name"));
        ret.add(new SelectItem("role", "role"));
        ret.add(new SelectItem("CIF", "CIF"));
        ret.add(new SelectItem("NIF", "NIF"));
        ret.add(new SelectItem("VID", "VID"));
        ret.add(new SelectItem("PID", "PID"));
        ret.add(new SelectItem("NODEID", "NODEID"));
        ret.add(new SelectItem("FABRICID", "FABRICID"));
        ret.add(new SelectItem("NOCCAT", "NOCCAT"));
        ret.add(new SelectItem("FirmwareSigningID", "FirmwareSigningID"));
        ret.add(new SelectItem("CertificationID", "CertificationID"));
        // UniqueIdentifier is left out, because we don't want people to use that
        return ret;
    }

    public boolean isExistsClientCertificateRenewalExtension() {
        return editionEjbBridgeSession.isRunningEnterprise();
    }

    public List<String> getAvailableSigningAlgorithms() {
        // Return all algorithms except the SHA1 ones (otherwise SHA1WithRSA would come first, and serve as a very bad default option)
        return new ArrayList<>(Arrays.asList(AlgorithmConstants.AVAILABLE_SIGALGS).stream().filter(
                sigalg -> !sigalg.startsWith(AlgorithmConstants.HASHALGORITHM_SHA1)).toList());
    }

    private ArrayList<Pair<Integer, String>> getAvailableTokens() {
        final ArrayList<Pair<Integer, String>> availableCryptoTokens = new ArrayList<>();
        for (CryptoTokenInfo current : cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken)) {
            if (current.isActive()
                    && authorizationSession.isAuthorizedNoLogging(authenticationToken,
                            CryptoTokenRules.USE.resource() + "/" + current.getCryptoTokenId())) {
                availableCryptoTokens.add(Pair.of(current.getCryptoTokenId(), current.getName()));
            }
        }
        availableCryptoTokens.sort((o1, o2) -> o1.getRight().compareToIgnoreCase(o2.getRight()));
        return availableCryptoTokens;
    }

    /**
     * Find all key aliases on tokenId that match the required usages and algorithm
     * 
     * @param tokenId token to search
     * @param requiredAlgorithm only keys matching this algorithm will be returned.  May be null.
     * @return List of matching key aliases
     */
    private ArrayList<String> getAvailableKeyAliases(Integer tokenId, String requiredAlgorithm) {
        final var availableKeys = new ArrayList<String>();
        try {
            CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(tokenId);
            for (String alias : cryptoToken.getAliases()) {
                String algorithm = cryptoToken.getPublicKey(alias).getAlgorithm();
                log.debug("Token:" + tokenId + " Key:" + alias + " Algorithm:" + algorithm + " requiredAlgorithm:" + requiredAlgorithm);
                if (algorithm.equals(requiredAlgorithm)) {
                    availableKeys.add(alias);
                }
            }
            availableKeys.sort(String::compareTo);
            return availableKeys;
        } catch (KeyStoreException | CryptoTokenOfflineException e) {
            log.error("Crypto token " + currentAlias.signingCryptoTokenId + " off line");
            return new ArrayList<>();
        }
    }

    public List<SelectItem> getAvailableEncryptionCryptoTokens() {
        return getAvailableTokens().stream().map(t -> new SelectItem(t.getKey(), t.getValue())).collect(Collectors.toList());
    }

    public List<SelectItem> getAvailableSigningCryptoTokens() {
        return getAvailableTokens().stream().map(t -> new SelectItem(t.getKey(), t.getValue())).collect(Collectors.toList());
    }

    public List<SelectItem> getAvailableSigningKeys() {
        if (currentAlias == null || currentAlias.signingCryptoTokenId == null || currentAlias.signingAlgorithm == null) {
            return new ArrayList<>();
        }
        return getAvailableKeyAliases(currentAlias.signingCryptoTokenId, AlgorithmTools.getKeyAlgorithmFromSigAlg(currentAlias.signingAlgorithm)).stream().map(a -> new SelectItem(a)).toList();
    }

    public List<SelectItem> getAvailableEncryptionKeys() {
        if (currentAlias == null || currentAlias.encryptionCryptoTokenId == null) {
            return new ArrayList<>();
        }
        return getAvailableKeyAliases(currentAlias.encryptionCryptoTokenId, "RSA").stream().map(a -> new SelectItem(a)).toList();
    }

    public String getCurrentAliasEncryptionCryptoTokenName() {
        if (currentAlias == null || currentAlias.encryptionCryptoTokenId == null) {
            return "";
        }
        return cryptoTokenManagementSession.getCryptoTokenInfo(currentAlias.encryptionCryptoTokenId).getName();
    }

    public String getCurrentAliasSigningCryptoTokenName() {
        if (currentAlias == null || currentAlias.signingCryptoTokenId == null) {
            return "";
        }
        return cryptoTokenManagementSession.getCryptoTokenInfo(currentAlias.signingCryptoTokenId).getName();
    }

    public Collection<SelectItem> getAllCas() {
        List<SelectItem> sortedCas = new ArrayList<>();
        final Map<Integer, String> caIdToName = caSession.getCAIdToNameMap();
        final List<Integer> authorizedCaIds = caSession.getAuthorizedCaIds(getAdmin());
        for (Integer id : authorizedCaIds) {
            final String name = caIdToName.get(id);
            sortedCas.add(new SelectItem(id, name));
        }
        sortedCas.sort((o1, o2) -> o1.getLabel().compareToIgnoreCase(o2.getLabel()));
        return sortedCas;
    }
}
