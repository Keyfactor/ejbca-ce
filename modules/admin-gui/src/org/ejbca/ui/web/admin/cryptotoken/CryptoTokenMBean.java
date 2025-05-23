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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.File;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Collectors;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.KeyGenParams.KeyGenParamsBuilder;
import com.keyfactor.util.keys.token.KeyGenParams.KeyPairTemplate;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabel;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.accounts.AccountBindingException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keys.token.AvailableCryptoToken;
import org.cesecore.keys.token.AwsKmsAuthenticationType;
import org.cesecore.keys.token.AzureAuthenticationType;
import org.cesecore.keys.token.AzureCryptoToken;
import org.cesecore.keys.token.CryptoTokenConstants;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSession;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBinding;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.util.SlotList;

import jakarta.ejb.EJBException;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.context.FacesContext;
import jakarta.faces.model.ListDataModel;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;

/**
 * JavaServer Faces Managed Bean for managing CryptoTokens.
 * Session scoped and will cache the list of tokens and keys.
 */
@Named
@ViewScoped
public class CryptoTokenMBean extends BaseManagedBean implements Serializable {

    public String localize(String stringId) {
        return getEjbcaWebBean().getText(stringId);
    }

    public class KeyBindingGuiInfo {

    }

    private static final String CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX = "CRYPTOTOKEN_LABEL_TYPE_";

    public CryptoTokenMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, CryptoTokenRules.VIEW.resource());
    }

    public void onload() {
        FacesContext fc = FacesContext.getCurrentInstance();
        Map<String, String> params = fc.getExternalContext().getRequestParameterMap();
        String initNewPkiParam = params.get("initNewPki");
        if (StringUtils.equals(initNewPkiParam, "true")) {
            initNewPki = true;
        }
    }

    /**
     * GUI table representation of a CryptoToken that can be interacted with.
     */
    public class CryptoTokenGuiInfo {
        private final CryptoTokenInfo cryptoTokenInfo;
        private final String p11LibraryAlias;
        private final boolean allowedActivation;
        private final boolean allowedDeactivation;
        private String authenticationCode;
        private final boolean referenced;
        private boolean requiresSecretToActivate;

        private CryptoTokenGuiInfo(CryptoTokenInfo cryptoTokenInfo, String p11LibraryAlias, boolean allowedActivation, boolean allowedDectivation, boolean referenced, boolean requiresSecretToActivate) {
            this.cryptoTokenInfo = cryptoTokenInfo;
            this.p11LibraryAlias = p11LibraryAlias;
            this.allowedActivation = allowedActivation;
            this.allowedDeactivation = allowedDectivation;
            this.referenced = referenced;
            this.requiresSecretToActivate = requiresSecretToActivate;
        }

        public String getStatusImg() {
            return getEjbcaWebBean().getImagePath(isActive() ? "status-ca-active.png" : "status-ca-offline.png");
        }

        public String getAutoActivationYesImg() {
            return getEjbcaWebBean().getImagePath("status-ca-active.png");
        }

        public Integer getCryptoTokenId() {
            return cryptoTokenInfo.getCryptoTokenId();
        }

        public String getTokenName() {
            return cryptoTokenInfo.getName();
        }

        public boolean isActive() {
            return cryptoTokenInfo.isActive();
        }

        public boolean isAutoActivation() {
            return cryptoTokenInfo.isAutoActivation();
        }

        public String getTokenType() {
            return cryptoTokenInfo.getType();
        }

        /**
         * @return A string representing slot:index:label for a P11 slot
         */
        public String getP11Slot() {
            return cryptoTokenInfo.getP11Slot();
        }

        public String getP11SlotLabelType() {
            return cryptoTokenInfo.getP11SlotLabelType();
        }

        public String getP11SlotLabelTypeText() {
            if (!isP11SlotType()) {
                return "";
            }
            return EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + cryptoTokenInfo.getP11SlotLabelType());
        }

        public String getP11LibraryAlias() {
            return p11LibraryAlias;
        }

        public String getKeyVaultType() {
            return cryptoTokenInfo.getKeyVaultType();
        }

        public String getKeyVaultName() {
            return cryptoTokenInfo.getKeyVaultName();
        }

        public String getKeyVaultClientID() {
            return cryptoTokenInfo.getKeyVaultClientID();
        }

        public String getSecurosysRestApiName() {
            return cryptoTokenInfo.getSecurosysRestApiName();
        }

        public String getSecurosysAuthType() {
            return cryptoTokenInfo.getSecurosysAuthType();
        }

        public String getSecurosysAuthCert() {
            return cryptoTokenInfo.getSecurosysAuthCert();
        }

        public String getSecurosysManagementKey() {
            return cryptoTokenInfo.getSecurosysManagementKey();
        }

        public String getSecurosysOperationKey() {
            return cryptoTokenInfo.getSecurosysOperationKey();
        }

        public String getSecurosysServiceKey() {
            return cryptoTokenInfo.getSecurosysServiceKey();
        }

        public String getSecurosysApprovalTimeout() {
            return cryptoTokenInfo.getSecurosysApprovalTimeout();
        }

        public String getAuthenticationCode() {
            if (!requiresSecretToActivate) {
                return AzureCryptoToken.DUMMY_ACTIVATION_CODE;
            }
            return authenticationCode;
        }

        public void setAuthenticationCode(String authenticationCode) {
            this.authenticationCode = authenticationCode;
        }

        public boolean isAllowedActivation() {
            return allowedActivation;
        }

        public boolean isAllowedDeactivation() {
            return allowedDeactivation;
        }

        public boolean isReferenced() {
            return referenced;
        }

        public boolean isP11SlotType() {
            return PKCS11CryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType()) ||
                    CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(cryptoTokenInfo.getType());
        }

        public boolean isP11NG() {
            return CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(cryptoTokenInfo.getType());
        }

        public boolean isAzureType() {
            return AzureCryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType());
        }

        public boolean isSecurosysType() {
            return CryptoTokenFactory.SECUROSYS_SIMPLE_NAME.equals(cryptoTokenInfo.getType());
        }

        public boolean isFortanixType() {
            return CryptoTokenFactory.FORTANIX_SIMPLE_NAME.equals(cryptoTokenInfo.getType());
        }

        public boolean isAWSKMSType() {
            return CryptoTokenFactory.AWSKMS_SIMPLE_NAME.equals(cryptoTokenInfo.getType());
        }

        public boolean isRequiresSecretToActivate() {
            return requiresSecretToActivate;
        }

        public void setRequiresSecretToActivate(boolean requiresSecretToActivate) {
            this.requiresSecretToActivate = requiresSecretToActivate;
        }

        public boolean isCanReactivate() {
            // if its not an auto-activate token, we show the activate/deactivate buttons, no the reactivate button
            if (!isAutoActivation())
                return false;

            // for AWSKMS auto-activate tokens that don't take a secret, it makes no sense to show a reactivate button
            if (CryptoTokenFactory.AWSKMS_SIMPLE_NAME.equals(cryptoTokenInfo.getType()) && !requiresSecretToActivate)
                return false;

            // for now, show reactivate for all other token types
            return true;
        }
    }

    /**
     * GUI edit/view representation of a CryptoToken that can be interacted with.
     */
    public class CurrentCryptoTokenGuiInfo {
        private String name = "";
        private String type = SoftCryptoToken.class.getSimpleName();
        private String secret1 = "";
        private String secret2 = "";
        private boolean autoActivate = false;
        private boolean allowExportPrivateKey = false;
        private String p11Library = "";
        private String p11Slot = WebConfiguration.getDefaultP11SlotNumber();
        private Pkcs11SlotLabelType p11SlotLabelType = Pkcs11SlotLabelType.SLOT_NUMBER;
        private String p11AttributeFile = "default";
        private boolean active = false;
        private boolean referenced = false;
        private String keyPlaceholders;
        private boolean allowExplicitParameters = false;
        private boolean canGenerateKey = true;
        private String canGenerateKeyMsg = null;
        private String keyVaultType = "premium";
        private String keyVaultName = "ejbca-keyvault";
        private String keyVaultClientID = "";
        private String keyVaultKeyBinding = "";
        private String fortanixBaseAddress = "https://apps.smartkey.io"; // default value
        private String awsKMSRegion = "us-east-1"; // default value
        private String awsKMSAccessKeyID = ""; // default value
        private AzureAuthenticationType azureAuthenticationType = AzureAuthenticationType.APP_ID_AND_SECRET;
        private AwsKmsAuthenticationType awsKmsAuthenticationType = AwsKmsAuthenticationType.KEY_ID_AND_SECRET;


        private String securosysRestApi = "https://primusdev.cloudshsm.com";
        private String securosysAuthenticationType = "TOKEN";
        private String securosysAuthCert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
        private String securosysManagementKey = "";
        private String securosysOperationKey = "";
        private String securosysServiceKey = "";
        private String securosysApprovalTimeout = "";


        public String getSecurosysRestApi() {
            return securosysRestApi;
        }

        public void setSecurosysRestApi(String securosysRestApi) {
            this.securosysRestApi = securosysRestApi;
        }

        public String getSecurosysAuthenticationType() {
            return securosysAuthenticationType;
        }

        public void setSecurosysAuthenticationType(String securosysAuthenticationType) {
            this.securosysAuthenticationType = securosysAuthenticationType;
        }

        public String getSecurosysAuthCert() {
            return securosysAuthCert;
        }

        public void setSecurosysAuthCert(String securosysAuthCert) {
            this.securosysAuthCert = securosysAuthCert;
        }

        public String getSecurosysManagementKey() {
            return securosysManagementKey;
        }

        public void setSecurosysManagementKey(String securosysManagementKey) {
            this.securosysManagementKey = securosysManagementKey;
        }

        public String getSecurosysOperationKey() {
            return securosysOperationKey;
        }

        public void setSecurosysOperationKey(String securosysOperationKey) {
            this.securosysOperationKey = securosysOperationKey;
        }

        public String getSecurosysServiceKey() {
            return securosysServiceKey;
        }

        public void setSecurosysServiceKey(String securosysServiceKey) {
            this.securosysServiceKey = securosysServiceKey;
        }

        public String getSecurosysApprovalTimeout() {
            return securosysApprovalTimeout;
        }

        public void setSecurosysApprovalTimeout(String securosysApprovalTimeout) {
            this.securosysApprovalTimeout = securosysApprovalTimeout;
        }

        private CurrentCryptoTokenGuiInfo() {
        }

        public AzureAuthenticationType[] getAzureAuthenticationTypes() {
            return AzureAuthenticationType.values();
        }

        public AwsKmsAuthenticationType[] getAwsKmsAuthenticationTypes() {
            return AwsKmsAuthenticationType.values();
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getSecret1() {
            return secret1;
        }

        public void setSecret1(String secret1) {
            this.secret1 = secret1;
        }

        public String getSecret2() {
            return secret2;
        }

        public void setSecret2(String secret2) {
            this.secret2 = secret2;
        }

        public boolean isAutoActivate() {
            return autoActivate;
        }

        public void setAutoActivate(boolean autoActivate) {
            this.autoActivate = autoActivate;
        }

        public boolean isAllowExportPrivateKey() {
            return allowExportPrivateKey;
        }

        public void setAllowExportPrivateKey(boolean allowExportPrivateKey) {
            this.allowExportPrivateKey = allowExportPrivateKey;
        }

        public String getP11Library() {
            return p11Library;
        }

        public void setP11Library(String p11Library) {
            this.p11Library = p11Library;
        }

        public String getP11Slot() {
            return p11Slot;
        }

        public void setP11Slot(String p11Slot) {
            this.p11Slot = p11Slot;
        }

        public String getP11SlotLabelType() {
            return p11SlotLabelType.getKey();
        }

        public void setP11SlotLabelType(String p11SlotLabelType) {
            this.p11SlotLabelType = Pkcs11SlotLabelType.getFromKey(p11SlotLabelType);
        }

        public String getP11SlotLabelTypeText() {
            return EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + getP11SlotLabelType());
        }

        public String getP11AttributeFile() {
            return p11AttributeFile;
        }

        public void setP11AttributeFile(String p11AttributeFile) {
            this.p11AttributeFile = p11AttributeFile;
        }

        public void setKeyVaultType(String keyVaultType) {
            this.keyVaultType = keyVaultType;
        }

        public void setKeyVaultName(String keyVaultName) {
            this.keyVaultName = keyVaultName;
        }

        public void setKeyVaultClientID(String keyVaultClientID) {
            this.keyVaultClientID = keyVaultClientID;
        }

        public String getAWSKMSRegion() {
            return awsKMSRegion;
        }

        public void setAWSKMSRegion(String awsKMSRegion) {
            this.awsKMSRegion = awsKMSRegion;
        }

        public void setAWSKMSAccessKeyID(String awsKMSAccessKeyID) {
            this.awsKMSAccessKeyID = awsKMSAccessKeyID;
        }

        public String getAWSKMSAccessKeyID() {
            return awsKMSAccessKeyID;
        }


        public boolean isActive() {
            return active;
        }

        public void setActive(boolean active) {
            this.active = active;
        }

        public boolean isReferenced() {
            return referenced;
        }

        public void setReferenced(boolean referenced) {
            this.referenced = referenced;
        }

        public String getKeyPlaceholders() {
            return keyPlaceholders;
        }

        public void setKeyPlaceholders(String keyTemplates) {
            this.keyPlaceholders = keyTemplates;
        }

        public boolean isAllowExplicitParameters() {
            return allowExplicitParameters;
        }

        public void setAllowExplicitParameters(boolean allowExplicitParameters) {
            this.allowExplicitParameters = allowExplicitParameters;
        }

        public boolean isCanGenerateKey() {
            return canGenerateKey;
        }

        public void setCanGenerateKey(boolean canGenerateKey) {
            this.canGenerateKey = canGenerateKey;
        }

        public void setCanGenerateKeyMsg(String msg) {
            this.canGenerateKeyMsg = msg;
        }

        public String getCanGenerateKeyMsg() {
            return canGenerateKeyMsg;
        }

        public String getP11LibraryAlias() {
            return CryptoTokenMBean.this.getP11LibraryAlias(p11Library);
        }

        public String getP11AttributeFileAlias() {
            return CryptoTokenMBean.this.getP11AttributeFileAlias(p11AttributeFile);
        }

        public String getKeyVaultType() {
            return keyVaultType;
        }

        public String getKeyVaultName() {
            return keyVaultName;
        }

        public String getKeyVaultClientID() {
            return keyVaultClientID;
        }

        public String getFortanixBaseAddress() {
            return fortanixBaseAddress;
        }

        public boolean isShowSoftCryptoToken() {
            return SoftCryptoToken.class.getSimpleName().equals(getType());
        }

        public boolean isShowP11CryptoToken() {
            return PKCS11CryptoToken.class.getSimpleName().equals(getType()) ||
                    CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(getType());
        }

        public boolean isShowP11NGCryptoToken() {
            return CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(getType());
        }

        public boolean isShowAzureCryptoToken() {
            return AzureCryptoToken.class.getSimpleName().equals(getType());
        }

        public boolean isShowAWSKMSCryptoToken() {
            return CryptoTokenFactory.AWSKMS_SIMPLE_NAME.equals(getType());
        }

        public boolean isShowFortanixCryptoToken() {
            return CryptoTokenFactory.FORTANIX_SIMPLE_NAME.equals(getType());
        }

        public boolean isShowSecurosysCryptoToken() {
            return CryptoTokenFactory.SECUROSYS_SIMPLE_NAME.equals(getType());
        }

        public boolean getShowBearerToken() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME) && !securosysAuthenticationType.equals("CERT");
        }

        public boolean getShowCert() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME) && !securosysAuthenticationType.equals("TOKEN");
        }

        public boolean getShowKey() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME) && !securosysAuthenticationType.equals("TOKEN");
        }

        public boolean getShowManagementKey() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME);
        }

        public boolean getShowOperationKey() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME);
        }

        public boolean getShowServiceKey() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME);
        }

        public boolean getShowApprovalTimeout() {
            return type.equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME);
        }

        public boolean isSlotOfTokenLabelType() {
            return p11SlotLabelType.equals(Pkcs11SlotLabelType.SLOT_LABEL);
        }

        // If P11NG crypto token and Utimaco CP5 functions enabled
        public boolean isShowAuthorizationInfo() {
            return CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(getType()) && WebConfiguration.isP11NGUtimacoCP5Enabled();
        }

        public String getKeyVaultKeyBinding() {
            return keyVaultKeyBinding;
        }

        public String getKeyVaultKeyBindingName() {
            for (SelectItem binding : getInternalKeyBindings()) {
                if (binding.getValue().toString().equals(keyVaultKeyBinding))
                    return binding.getLabel();
            }
            return "binding " + keyVaultKeyBinding + " not found";
        }

        public void setKeyVaultKeyBinding(String keyVaultKeyBinding) {
            this.keyVaultKeyBinding = keyVaultKeyBinding;
        }

        public String getAwsKmsAuthenticationType() {
            return awsKmsAuthenticationType.toString();
        }

        public void setAwsKmsAuthenticationType(AwsKmsAuthenticationType awsKmsAuthenticationType) {
            this.awsKmsAuthenticationType = awsKmsAuthenticationType;
        }

        public void setAwsKmsAuthenticationType(String awsKmsAuthenticationType) {
            this.awsKmsAuthenticationType = AwsKmsAuthenticationType.valueOf(awsKmsAuthenticationType);
        }

        public String getAzureAuthenticationType() {
            return azureAuthenticationType.toString();
        }

        public void setAzureAuthenticationType(AzureAuthenticationType azureAuthenticationType) {
            this.azureAuthenticationType = azureAuthenticationType;
        }

        public void setAzureAuthenticationType(String azureAuthenticationTypeString) {
            this.azureAuthenticationType = AzureAuthenticationType.valueOf(azureAuthenticationTypeString);
        }

        public boolean getRequiresSecret() {
            // true for crypto tokens that require some kind of activation code.  Azure and AWS may not
            if (type.equals(AzureCryptoToken.class.getSimpleName()) && azureAuthenticationType != AzureAuthenticationType.APP_ID_AND_SECRET) {
                return false;
            } else if (type.equals(CryptoTokenFactory.AWSKMS_SIMPLE_NAME) && awsKmsAuthenticationType != AwsKmsAuthenticationType.KEY_ID_AND_SECRET) {
                return false;
            } else {
                return true;
            }
        }

        public boolean getShowKeyBinding() {
            return !type.equals(AzureCryptoToken.class.getSimpleName()) || azureAuthenticationType == AzureAuthenticationType.KEY_BINDING;
        }

        public boolean getShowClientId() {
            return !type.equals(AzureCryptoToken.class.getSimpleName()) || azureAuthenticationType != AzureAuthenticationType.MANAGED_IDENTITY;
        }

        public void setFortanixBaseAddress(String fortanixBaseAddress) {
            this.fortanixBaseAddress = fortanixBaseAddress;
        }
    }

    /**
     * Selectable key pair GUI representation
     */
    public class KeyPairGuiInfo {
        private final String alias;
        private final String keyAlgorithm;
        private final String keySpecification; // to be displayed in GUI
        private final String rawKeySpec; // to be used for key generation
        private final String subjectKeyID;
        private final boolean placeholder;
        private boolean selected = false;
        private int selectedKakCryptoTokenId;
        private String keyUsage = null;
        private String selectedKakKeyAlias;
        private String selectedPaddingScheme;
        private boolean initialized;
        private boolean authorized;
        private KeyPairGuiInfo(KeyPairInfo keyPairInfo) {
            alias = keyPairInfo.getAlias();
            keyAlgorithm = keyPairInfo.getKeyAlgorithm();
            rawKeySpec = keyPairInfo.getKeySpecification();
            if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyPairInfo.getKeyAlgorithm())) {
                keySpecification = getEcKeySpecAliases(rawKeySpec);
            } else {
                keySpecification = rawKeySpec;
            }
            subjectKeyID = keyPairInfo.getSubjectKeyID();
            if (keyPairInfo.getKeyUsage() != null) {
                keyUsage = keyPairInfo.getKeyUsage().toString();
            }
            placeholder = false;
            initialized = cryptoTokenManagementSession.isKeyInitialized(authenticationToken, getCurrentCryptoTokenId(), alias);
        }

        /**
         * Creates a placeholder with a template string, in the form of "alias;keyspec".
         * Placeholders are created in CryptoTokens that are imported from Statedump.
         */
        private KeyPairGuiInfo(String templateString) {
            String[] pieces = templateString.split("[" + CryptoToken.KEYPLACEHOLDERS_INNER_SEPARATOR + "]");
            alias = pieces[0];
            keyAlgorithm = KeyTools.keyspecToKeyalg(pieces[1]);
            rawKeySpec = KeyTools.shortenKeySpec(pieces[1]);
            if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
                keySpecification = getEcKeySpecAliases(rawKeySpec);
            } else {
                keySpecification = rawKeySpec;
            }
            keyUsage = pieces.length >= 3 ? pieces[2] : null;
            subjectKeyID = "";
            placeholder = true;
            initialized = false;
        }

        public List<SelectItem> getAvailableKeyAliases() {
            List<SelectItem> availableKeyAliases = new ArrayList<>();
            if (selectedKakCryptoTokenId != 0) {
                try {
                    final List<String> aliases = new ArrayList<>(cryptoTokenManagementSession.getKeyPairAliases(authenticationToken, selectedKakCryptoTokenId));
                    Collections.sort(aliases);
                    for (final String keyAlias : aliases) {
                        availableKeyAliases.add(new SelectItem(keyAlias));
                    }
                } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                    log.debug("Crypto Token is not usable. Can't list key aliases", e);
                }
            }
            availableKeyAliases.add(0, new SelectItem(null, "-Select Key Alias-"));
            return availableKeyAliases;
        }

        public List<SelectItem> getAvailablePaddingSchemes() {
            availablePaddingSchemes = new ArrayList<>();
            availablePaddingSchemes.add(0, new SelectItem("PKCS#1"));
            availablePaddingSchemes.add(0, new SelectItem("PSS"));
            return availablePaddingSchemes;
        }

        public String getAlias() {
            return alias;
        }

        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public String getKeySpecification() {
            return keySpecification;
        }
        public String getKeyUsage() {
            return keyUsage;
        }

        public String getRawKeySpec() {
            return rawKeySpec;
        }

        public String getSubjectKeyID() {
            return subjectKeyID;
        }

        public String getSelectedKakKeyAlias() {
            return selectedKakKeyAlias;
        }

        public String getSelectedPaddingScheme() {
            return selectedPaddingScheme;
        }

        public boolean isPlaceholder() {
            return placeholder;
        }

        public boolean isSelected() {
            return selected;
        }

        public void setSelected(boolean selected) {
            this.selected = selected;
        }

        public int getSelectedKakCryptoTokenId() {
            return selectedKakCryptoTokenId;
        }

        public void setSelectedKakCryptoTokenId(int selectedKakCryptoTokenId) {
            this.selectedKakCryptoTokenId = selectedKakCryptoTokenId;
        }

        public void setSelectedKakKeyAlias(String selectedKakKeyAlias) {
            this.selectedKakKeyAlias = selectedKakKeyAlias;
        }

        public void setSelectedPaddingScheme(String selectedPaddingScheme) {
            this.selectedPaddingScheme = selectedPaddingScheme;
        }

        public boolean isInitialized() {
            return initialized;
        }

        public boolean isAuthorized() {
            return authorized;
        }
    }

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CryptoTokenMBean.class);

    private ListDataModel<CryptoTokenGuiInfo> cryptoTokenGuiList = null;
    private List<KeyPairGuiInfo> keyPairGuiInfos = new ArrayList<>();
    private ListDataModel<KeyPairGuiInfo> keyPairGuiList = null;
    private List<SelectItem> availablePaddingSchemes;
    private List<SelectItem> internalKeyBindings = null;
    private String keyPairGuiListError = null;
    private int currentCryptoTokenId = 0;
    private CurrentCryptoTokenGuiInfo currentCryptoToken = null;
    private KeyPairGuiInfo currentKeyPairGuiInfo = null;
    private boolean p11SlotUsed = false; // Note if the P11 slot is already used by another crypto token, forcing a confirm
    private boolean currentCryptoTokenEditMode = true;  // currentCryptoTokenId==0 from start
    private boolean authorizeInProgress = false;
    private boolean unlimitedOperations = true;
    private boolean initNewPki;
    private String maxOperationCount;
    private KeyPairTemplate keyPairTemplate; // Used for CP5 (same key cannot do encrypt/decrypt and sign/verify)

    private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = getEjbcaWebBean().getEjb().getCryptoTokenManagementSession();
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    private final AuthenticationToken authenticationToken = getAdmin();
    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession = getEjbcaWebBean().getEjb().getInternalKeyBindingMgmtSession();
    private final GlobalConfigurationSessionLocal globalConfigSession = getEjbcaWebBean().getEjb().getGlobalConfigurationSession();

    /**
     * Workaround to cache the items used to render the page long enough for actions to be able to use them, but reload on every page view.
     */
    public boolean isPageLoadResetTrigger() {
        flushCaches();
        return false;
    }

    /**
     * Force reload from underlying (cache) layer
     */
    private void flushCaches() {
        cryptoTokenGuiList = null;
        flushCurrent();
    }

    /**
     * Force reload from underlying (cache) layer for the current CryptoToken and its list of key pairs
     */
    private void flushCurrent() {
        keyPairGuiList = null;
        currentCryptoToken = null;
        p11SlotUsed = false;
        internalKeyBindings = null;
    }

    public void actionAuthorizeStart() {
        authorizeInProgress = true;
        currentKeyPairGuiInfo = keyPairGuiList.getRowData();
    }

    public void actionAuthorizeCancel() {
        authorizeInProgress = false;
        currentKeyPairGuiInfo = null;
    }

    public String actionBackToPkiInstallation() {
        // Only used while page was redirected from initnewpki.xhtml.
        // This bean is session scoped. Reset this value to hide button
        // later on in same session.
        initNewPki = false;
        return "back";
    }

    public boolean isInitNewPki() {
        return initNewPki;
    }

    public boolean isAuthorizeInProgress() {
        return authorizeInProgress;
    }

    public boolean isUnlimitedOperations() {
        return unlimitedOperations;
    }


    public void setUnlimitedOperations(boolean unlimitedOperations) {
        this.unlimitedOperations = unlimitedOperations;
    }

    /**
     * @return number of allowed operations for this key. -1 if 'Unlimited' is checked
     */
    public String getMaxOperationCount() {
        return unlimitedOperations ? "-1" : maxOperationCount;
    }

    public void setMaxOperationCount(final String maxOperationCount) {
        this.maxOperationCount = maxOperationCount;
    }

    public KeyPairTemplate getKeyUsage() {
        return keyPairTemplate;
    }

    public void setKeyUsage(final KeyPairTemplate keyUsage) {
        this.keyPairTemplate = keyUsage;
    }

    public List<SelectItem> getAvailableKeyUsages() {
        List<SelectItem> ret = new ArrayList<>(Arrays.asList(
                new SelectItem(null, EjbcaJSFHelper.getBean().getText().get("CRYPTOTOKEN_KPM_KU")),
                new SelectItem(KeyPairTemplate.SIGN, EjbcaJSFHelper.getBean().getText().get("CRYPTOTOKEN_KPM_KU_SIGN")),
                new SelectItem(KeyPairTemplate.ENCRYPT, EjbcaJSFHelper.getBean().getText().get("CRYPTOTOKEN_KPM_KU_ENC"))));
        if (!WebConfiguration.isP11NGUtimacoCP5Enabled()) {
            // Utimaco CP5 only limits key usage to either sign/verify or encrypt/decrypt, not both at the same time
            ret.add(new SelectItem(KeyPairTemplate.SIGN_ENCRYPT, EjbcaJSFHelper.getBean().getText().get("CRYPTOTOKEN_KPM_KU_SIGENC")));
        }
        return ret;
    }

    /**
     * @return a List of all CryptoToken Identifiers referenced by CAs.
     */
    private List<Integer> getReferencedCryptoTokenIds() {
        final List<Integer> ret = new ArrayList<>();
        // Add all CryptoToken ids referenced by CAs
        for (int caId : caSession.getAllCaIds()) {
            final CAInfo cainfo = caSession.getCAInfoInternal(caId);
            // We may have CAIds that can not be resolved to a real CA, for example CVC CAs on Community
            if (cainfo != null && cainfo.getCAToken() != null) {
                ret.add(cainfo.getCAToken().getCryptoTokenId());
            }
        }
        // Add all CryptoToken ids referenced by InternalKeyBindings
        for (final String internalKeyBindingType : internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet()) {
            ret.addAll(internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(internalKeyBindingType)
                    .stream()
                    .map(InternalKeyBindingInfo::getCryptoTokenId)
                    .collect(Collectors.toList()));
        }
        // In the future other components that use CryptoTokens should be checked here as well!
        return ret;
    }


    /**
     * Used for selecting KAK crypto token.
     *
     * @return List of all available crypto tokens
     */
    public List<SelectItem> getAvailableCryptoTokens() {
        List<SelectItem> availableCryptoTokens = new ArrayList<>();
        // Don't allow entries in this token
        availableCryptoTokens.addAll(cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken)
                .stream()
                .filter(cryptoTokenInfo -> cryptoTokenInfo.getCryptoTokenId() != currentCryptoTokenId)
                .map(cryptoTokenInfo -> new SelectItem(cryptoTokenInfo.getCryptoTokenId(), cryptoTokenInfo.getName()))
                .collect(Collectors.toList()));
        Collections.sort(availableCryptoTokens, (o1, o2) -> o1.getLabel().compareToIgnoreCase(o2.getLabel()));
        availableCryptoTokens.add(0, new SelectItem(null, "-Select Crypto Token-"));
        return availableCryptoTokens;
    }


    /**
     * Build a list sorted by name from the authorized cryptoTokens that can be presented to the user
     */
    public ListDataModel<CryptoTokenGuiInfo> getCryptoTokenGuiList() {
        if (cryptoTokenGuiList == null) {
            final List<Integer> referencedCryptoTokenIds = getReferencedCryptoTokenIds();
            final List<CryptoTokenGuiInfo> list = new ArrayList<>();
            for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken)) {
                final String p11LibraryAlias = getP11LibraryAlias(cryptoTokenInfo.getP11Library());
                final boolean allowedActivation = authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.ACTIVATE + "/" + cryptoTokenInfo.getCryptoTokenId().toString());
                final boolean allowedDeactivation = authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.DEACTIVATE + "/" + cryptoTokenInfo.getCryptoTokenId().toString());
                final boolean referenced = referencedCryptoTokenIds.contains(cryptoTokenInfo.getCryptoTokenId());
                final boolean requiresSecretToActivate = cryptoTokenInfo.requiresSecretToActivate();
                list.add(new CryptoTokenGuiInfo(cryptoTokenInfo, p11LibraryAlias, allowedActivation, allowedDeactivation, referenced, requiresSecretToActivate));
                Collections.sort(list, (cryptoTokenInfo1, cryptoTokenInfo2) -> cryptoTokenInfo1.getTokenName().compareToIgnoreCase(cryptoTokenInfo2.getTokenName()));
            }
            cryptoTokenGuiList = new ListDataModel<>(list);
        }
        // If show the list, then we are on the main page and want to flush the two caches
        flushCurrent();
        setCurrentCryptoTokenEditMode(false);
        return cryptoTokenGuiList;
    }

    /**
     * Build a list sorted by name of the internal key bindings that can be used for public key authentication to Azure crypto tokens.
     */
    public List<SelectItem> getInternalKeyBindings() {
        if (internalKeyBindings == null) {
            internalKeyBindings = internalKeyBindingMgmtSession
                    .getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS)
                    .stream()
                    .sorted((b1, b2) -> b1.getName().compareTo(b2.getName()))
                    .map(b -> new SelectItem(b.getId(), b.getName()))
                    .collect(Collectors.toList());
        }
        return internalKeyBindings;
    }

    /**
     * Invoked when admin requests a CryptoToken activation.
     */
    public void activateCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList != null) {
            final CryptoTokenGuiInfo current = cryptoTokenGuiList.getRowData();
            if (current != null) {
                try {
                    cryptoTokenManagementSession.activate(authenticationToken, current.getCryptoTokenId(), current.getAuthenticationCode().toCharArray());
                } catch (CryptoTokenOfflineException e) {
                    final String msg = "Activation of CryptoToken '" + current.getTokenName() + "' (" + current.getCryptoTokenId() +
                            ") by administrator " + authenticationToken.toString() + " failed. Device was unavailable.";
                    super.addNonTranslatedErrorMessage(msg);
                    log.info(msg + " Base message: " + e.getMessage());
                } catch (CryptoTokenAuthenticationFailedException e) {
                    final String msg = "Activation of CryptoToken '" + current.getTokenName() + "' (" + current.getCryptoTokenId() +
                            ") by administrator " + authenticationToken.toString() + " failed. Either the authentication " +
                            "code was wrong or you forgot to provide a smart card or PED key.";
                    super.addNonTranslatedErrorMessage(msg);
                    log.info(msg + " Base message: " + e.getMessage());
                }
                flushCaches();
            }
        }
    }

    /**
     * Invoked when admin requests a CryptoToken deactivation.
     */
    public void deactivateCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList != null) {
            final CryptoTokenGuiInfo rowData = cryptoTokenGuiList.getRowData();
            cryptoTokenManagementSession.deactivate(authenticationToken, rowData.getCryptoTokenId());
            flushCaches();
        }
    }

    /**
     * Invoked when admin requests a CryptoToken deletion.
     */
    public void deleteCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList != null) {
            final CryptoTokenGuiInfo rowData = cryptoTokenGuiList.getRowData();
            // Check references in ACME EAB with symmetric key.
            final List<String> references = referencedAcmeConfigurationIDs(rowData.getCryptoTokenId());
            if (references.size() == 0) {
                cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, rowData.getCryptoTokenId());
            } else {
                addErrorMessage("CRYPTOTOKEN_COULD_NOT_BE_DELETED_BECAUSE_REFERENCE_IN_ACME_ALIAS", String.join(", ", references));
            }
            flushCaches();
        }
    }

    /**
     * Returns a list of all crypto token references in ACME configurations external account bindings
     * of type AcmeEabWithHMac, if key encryption is enabled.
     *
     * @param cryptoTokenId the ID of the crypto tokens entity.
     * @return a list containing all ACME configuration IDs or an empty list.
     */
    private List<String> referencedAcmeConfigurationIDs(final int cryptoTokenId) {
        final List<String> result = new ArrayList<>();
        final GlobalAcmeConfiguration globalConfig = (GlobalAcmeConfiguration)
                globalConfigSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
        AcmeConfiguration acmeAlias;
        if (globalConfig == null) {
            return result;
        }
        for (String acmeAliasId : globalConfig.getAcmeConfigurationIds()) {
            acmeAlias = globalConfig.getAcmeConfiguration(acmeAliasId);
            if (acmeAlias != null) {
                try {
                    final List<AcmeExternalAccountBinding> eabs = acmeAlias.getExternalAccountBinding();
                    if (eabs != null) {
                        for (AcmeExternalAccountBinding eab : eabs) {
                            final Object encryptKey = eab.getDataMap().get("encryptKey");
                            if ("ACME_EAB_RFC_COMPLIANT".equals(eab.getAccountBindingTypeIdentifier())
                                    && encryptKey != null && (Boolean) encryptKey
                                    && Integer.toString(cryptoTokenId).equals(eab.getDataMap().get("encryptionKeyId"))) {
                                result.add(acmeAlias.getConfigurationId());
                            }
                        }
                    }
                } catch (AccountBindingException e) {
                    log.warn("Could not load ACME EAB '" + acmeAliasId
                            + "' to verify if it contains a reference to the crypto token to be deleted.");
                }
            }
        }
        return result;
    }

    /**
     * @return true if admin may create new or modify existing CryptoTokens.
     */
    public boolean isAllowedToModify() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource());
    }

    /**
     * @return true if admin may delete CryptoTokens.
     */
    public boolean isAllowedToDelete() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.DELETE_CRYPTOTOKEN.resource());
    }

    public void saveCurrentCryptoTokenWithCheck() throws AuthorizationDeniedException {
        saveCurrentCryptoToken(true);
    }

    public void saveCurrentCryptoToken() throws AuthorizationDeniedException {
        saveCurrentCryptoToken(false);
    }

    /**
     * Invoked when admin requests a CryptoToken creation.
     */
    private void saveCurrentCryptoToken(boolean checkSlotInUse) throws AuthorizationDeniedException {
        if (getCurrentCryptoToken().getRequiresSecret() && !getCurrentCryptoToken().getSecret1().equals(getCurrentCryptoToken().getSecret2())) {
            addNonTranslatedErrorMessage("Authentication codes do not match!");
            return;
        }
        try {
            final String name = getCurrentCryptoToken().getName();
            if (StringUtils.isBlank(name)) {
                addNonTranslatedErrorMessage("Error: Crypto Token name may not be blank.");
                return;
            }


            final Properties properties = new Properties();
            String className = null;
            if (PKCS11CryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType()) ||
                    CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(getCurrentCryptoToken().getType())) {
                className = getCurrentCryptoToken().getType().equals("PKCS11CryptoToken")
                        ? PKCS11CryptoToken.class.getName()
                        : CryptoTokenFactory.JACKNJI_NAME;
                String library = getCurrentCryptoToken().getP11Library();
                properties.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, library);
                String slotTextValue = getCurrentCryptoToken().getP11Slot().trim();
                String slotLabelType = getCurrentCryptoToken().getP11SlotLabelType();
                //Perform some name validation
                if (slotLabelType.equals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey())) {
                    if (!Pkcs11SlotLabelType.SLOT_NUMBER.validate(slotTextValue)) {
                        addNonTranslatedErrorMessage("Slot must be an absolute number");
                        return;
                    }
                } else if (slotLabelType.equals(Pkcs11SlotLabelType.SLOT_INDEX.getKey())) {
                    if (slotTextValue.charAt(0) != 'i') {
                        slotTextValue = "i" + slotTextValue;
                    }
                    if (!Pkcs11SlotLabelType.SLOT_INDEX.validate(slotTextValue)) {
                        addNonTranslatedErrorMessage("Slot must be an absolute number or use prefix 'i' for indexed slots.");
                        return;
                    }
                }

                // Verify that it is allowed
                final SlotList allowedSlots = getP11SlotList();
                if (allowedSlots != null) {
                    if (!StringUtils.isNumeric(slotTextValue)) {
                        log.info("An administrator attempted to create a crypto token with " + slotTextValue + " as slot reference. " +
                                "This failed because only slot number can be used as slot reference when the setting " +
                                "'cryptotoken.p11.lib.X.slotlist' is enabled in 'web.properties'.");
                        throw new IllegalArgumentException("Only slot number is allowed to be used as slot reference on this " +
                                "installation. Allowed slot numbers are: " + allowedSlots);
                    }
                    if (!allowedSlots.contains(slotTextValue)) {
                        throw new IllegalArgumentException("Slot number " + slotTextValue + " is not allowed. Allowed slots are: " + allowedSlots);
                    }
                }

                properties.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, slotTextValue);
                properties.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, slotLabelType);
                // The default should be null, but we will get a value "default" from the GUI code in this case..
                final String p11AttributeFile = getCurrentCryptoToken().getP11AttributeFile();
                if (!"default".equals(p11AttributeFile)) {
                    final File file = new File(p11AttributeFile);
                    if (!file.isFile() || !file.canRead()) {
                        addNonTranslatedErrorMessage("The attributes file " + p11AttributeFile + " does not exist or cannot be read. "
                                + "Make sure this file exists on the filesystem, and is readable by the application server.");
                    }
                    for (final String line : Files.readAllLines(Paths.get(p11AttributeFile), StandardCharsets.UTF_8)) {
                        if (line.startsWith("name")) {
                            addNonTranslatedErrorMessage(String.format("A name suffix of the provider instance should not be specified "
                                    + "when using a custom attributes file with EJBCA. Remove the line '%s'.", line));
                        }
                        if (line.startsWith("slot=") || line.startsWith("slot =")) {
                            addNonTranslatedErrorMessage(
                                    String.format("A slot ID to be associated with the provider instance should not be specified when "
                                            + "using a custom attributes file with EJBCA. Remove the line '%s'.", line));
                        }
                        if (line.startsWith("slotListIndex=") || line.startsWith("slotListIndex =")) {
                            addNonTranslatedErrorMessage(
                                    String.format("A slot index to be associated with the provider instance should not be specified when "
                                            + "using a custom attributes file with EJBCA. Remove the line '%s'.", line));
                        }
                        if (line.startsWith("library")) {
                            addNonTranslatedErrorMessage(
                                    String.format("A pathname to the PKCS11 implementation should not be specified when using a custom "
                                            + "attributes file with EJBCA. Remove the line '%s'.", line));
                        }
                    }
                    properties.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, p11AttributeFile);
                }
                if (checkSlotInUse) {
                    log.info("Checking if slot is already used");
                    List<String> usedBy = cryptoTokenManagementSession.isCryptoTokenSlotUsed(authenticationToken, name, className, properties);
                    if (!usedBy.isEmpty()) {
                        final StringBuilder msg = new StringBuilder("The P11 slot is already used by other crypto token(s)");
                        for (String cryptoTokenName : usedBy) {
                            String usedByName = cryptoTokenName;
                            if (NumberUtils.isNumber(usedByName)) {
                                // if the crypto token name is purely numeric, it is likely to be a database protection token
                                usedByName = usedByName + " (database protection?)";
                            }
                            msg.append("; ");
                            msg.append(usedByName);
                        }
                        msg.append(". Re-using P11 slots in multiple crypto tokens is discouraged, and all parameters must be identical. Re-enter authentication code and Confirm Save to continue.");
                        p11SlotUsed = true;
                        addNonTranslatedErrorMessage(msg.toString());
                        return;
                    }
                }
            } else if (SoftCryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType())) {
                className = SoftCryptoToken.class.getName();
            } else if (AzureCryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType())) {
                className = AzureCryptoToken.class.getName();
                final String vaultType = getCurrentCryptoToken().getKeyVaultType().trim();
                final String vaultName = getCurrentCryptoToken().getKeyVaultName().trim();
                final String vaultClientID = getCurrentCryptoToken().getKeyVaultClientID().trim();
                final String vaultKeyBinding = getCurrentCryptoToken().getKeyVaultKeyBinding();
                properties.setProperty(AzureCryptoToken.KEY_VAULT_TYPE, vaultType);
                properties.setProperty(AzureCryptoToken.KEY_VAULT_NAME, vaultName);
                properties.setProperty(AzureCryptoToken.KEY_VAULT_CLIENTID, vaultClientID);
                properties.setProperty(AzureCryptoToken.KEY_VAULT_AUTHENTICATION_TYPE, getCurrentCryptoToken().getAzureAuthenticationType().toString());
                if (vaultKeyBinding != null) {
                    properties.setProperty(AzureCryptoToken.KEY_VAULT_KEY_BINDING, vaultKeyBinding);
                }
            } else if (CryptoTokenFactory.AWSKMS_SIMPLE_NAME.equals(getCurrentCryptoToken().getType())) {
                className = CryptoTokenFactory.AWSKMS_NAME;
                String region = getCurrentCryptoToken().getAWSKMSRegion().trim();
                String keyid = getCurrentCryptoToken().getAWSKMSAccessKeyID().trim();
                properties.setProperty(CryptoTokenConstants.AWSKMS_REGION, region);
                properties.setProperty(CryptoTokenConstants.AWSKMS_ACCESSKEYID, keyid);
                properties.setProperty(CryptoTokenConstants.AWSKMS_AUTHENTICATION_TYPE, getCurrentCryptoToken().getAwsKmsAuthenticationType());
            } else if (CryptoTokenFactory.FORTANIX_SIMPLE_NAME.equals(getCurrentCryptoToken().getType())) {
                className = CryptoTokenFactory.FORTANIX_NAME;
                final String fortanixBaseAddress = getCurrentCryptoToken().getFortanixBaseAddress().trim();
                properties.setProperty(CryptoTokenConstants.FORTANIX_BASE_ADDRESS, fortanixBaseAddress);
            } else if (CryptoTokenFactory.SECUROSYS_SIMPLE_NAME.equals(getCurrentCryptoToken().getType())) {
                className = CryptoTokenFactory.SECUROSYS_NAME;
                final String securosysRestApi = getCurrentCryptoToken().getSecurosysRestApi().trim();
                final String securosysAuthenticationType = getCurrentCryptoToken().getSecurosysAuthenticationType().toUpperCase();
                final String securosysAuthCert = getCurrentCryptoToken().getSecurosysAuthCert().trim();
                final String securosysManagementKey = getCurrentCryptoToken().getSecurosysManagementKey().trim();
                final String securosysOperationKey = getCurrentCryptoToken().getSecurosysOperationKey().trim();
                final String securosysServiceKey = getCurrentCryptoToken().getSecurosysServiceKey().trim();
                final String securosysApprovalTimeout = getCurrentCryptoToken().getSecurosysApprovalTimeout().trim();
                properties.setProperty(CryptoTokenConstants.SECUROSYS_REST_API, securosysRestApi);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_AUTHENTICATION_TYPE, securosysAuthenticationType);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_AUTH_CERT, securosysAuthCert);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_MANAGEMENT_KEY, securosysManagementKey);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_OPERATION_KEY, securosysOperationKey);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_SERVICE_KEY, securosysServiceKey);
                properties.setProperty(CryptoTokenConstants.SECUROSYS_APPROVAL_TIMEOUT, securosysApprovalTimeout);
            }
            if (getCurrentCryptoToken().isAllowExportPrivateKey()) {
                properties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, String.valueOf(getCurrentCryptoToken().isAllowExportPrivateKey()));
            }
            if (getCurrentCryptoToken().getKeyPlaceholders() != null) {
                properties.setProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, getCurrentCryptoToken().getKeyPlaceholders());
            }
            if (getCurrentCryptoToken().isAllowExplicitParameters()) {
                properties.setProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS, String.valueOf(getCurrentCryptoToken().isAllowExplicitParameters()));
            }

            final char[] secret = getCurrentCryptoToken().getRequiresSecret()
                    ? getCurrentCryptoToken().getSecret1().toCharArray()
                    : AzureCryptoToken.DUMMY_ACTIVATION_CODE.toCharArray();
            if (getCurrentCryptoTokenId() == 0) {
                if (secret.length > 0) {
                    if (getCurrentCryptoToken().isAutoActivate()) {
                        BaseCryptoToken.setAutoActivatePin(properties, new String(secret), true);
                    }
                    currentCryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, name, className, properties, null, secret);
                    addNonTranslatedInfoMessage("Crypto token created successfully.");
                } else {
                    addNonTranslatedErrorMessage("You must provide an authentication code to create a crypto token.");
                    return;
                }
            } else {
                if (getCurrentCryptoToken().isAutoActivate()) {
                    if (secret.length > 0) {
                        BaseCryptoToken.setAutoActivatePin(properties, new String(secret), true);
                    } else {
                        // Indicate that we want to reuse current auto-pin if present
                        properties.put(CryptoTokenManagementSession.KEEP_AUTO_ACTIVATION_PIN, Boolean.TRUE.toString());
                    }
                }
                cryptoTokenManagementSession.saveCryptoToken(authenticationToken, getCurrentCryptoTokenId(), name, properties, secret);
                addNonTranslatedInfoMessage("Crypto token saved successfully.");
            }
            flushCaches();
            setCurrentCryptoTokenEditMode(false);
        } catch (CryptoTokenOfflineException e) {
            addNonTranslatedErrorMessage(e);
        } catch (CryptoTokenAuthenticationFailedException e) {
            addNonTranslatedErrorMessage(e);
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
        } catch (IllegalArgumentException e) {
            addNonTranslatedErrorMessage(e);
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
        }
    }

    /**
     * Invoked when admin cancels a CryptoToken create or edit.
     */
    public void cancelCurrentCryptoToken() {
        setCurrentCryptoTokenEditMode(false);
        flushCaches();
    }

    public boolean isAnyP11LibraryAvailable() {
        return !getAvailableCryptoTokenP11Libraries().isEmpty();
    }

    /**
     * @return a list of library SelectItems sort by display name for detected P11 libraries.
     */
    public List<SelectItem> getAvailableCryptoTokenP11Libraries() {
        final List<SelectItem> ret = WebConfiguration.getAvailableP11LibraryToAliasMap()
                .entrySet()
                .stream()
                .map(entry -> new SelectItem(entry.getKey(), entry.getValue().getAlias()))
                .collect(Collectors.toList());
        // Sort by display name
        ret.sort((s0, s1) -> String.valueOf(s0.getValue()).compareTo(String.valueOf(s1)));
        return ret;
    }

    /**
     * @return alias if present otherwise the filename
     */
    private String getP11LibraryAlias(String library) {
        if (library == null) {
            return "";
        }

        WebConfiguration.P11LibraryInfo libinfo = WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
        if (libinfo == null) return library;
        String alias = libinfo.getAlias();
        if (alias == null || alias.isEmpty()) return library;
        return alias;
    }

    /**
     * @return a list of library SelectItems sort by display name for detected P11 libraries.
     */
    public List<SelectItem> getAvailableCryptoTokenP11AttributeFiles() {
        final List<SelectItem> availableP11AttributeFiles = WebConfiguration.getAvailableP11AttributeFiles()
                .entrySet()
                .stream()
                .map(entry -> new SelectItem(entry.getKey(), entry.getValue()))
                .sorted((s0, s1) -> String.valueOf(s0.getValue()).compareTo(String.valueOf(s1)))
                .collect(Collectors.toList());
        availableP11AttributeFiles.add(0, new SelectItem("default", "Default"));
        return availableP11AttributeFiles;
    }

    public List<SelectItem> getAvailableCryptoTokenP11SlotLabelTypes() {
        final List<SelectItem> ret = new ArrayList<>();
        for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
            if (type.equals(Pkcs11SlotLabelType.SUN_FILE)) {
                // jeklund doesn't believe that this is used anywhere, but he might be wrong
                continue;
            }
            final String display = EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + type.name());
            ret.add(new SelectItem(type.name(), display));
        }
        return ret;
    }

    /**
     * Tries to retrieve the list of PKCS#11 slots (including token labels) using the Sun PKCS#11 Wrapper
     */
    public List<SelectItem> getAvailableCryptoTokenP11SlotTokenLabels() {
        final List<SelectItem> ret = new ArrayList<>();
        try {
            final File p11Library = new File(currentCryptoToken.getP11Library());
            SlotList allowedSlots = getP11SlotList();
            if (p11Library.exists()) {
                int index = 0;
                for (final String extendedTokenLabel : Pkcs11SlotLabel.getExtendedTokenLabels(p11Library)) {
                    // Returned list is in form "slotId;tokenLabel"
                    final String slotId = extendedTokenLabel.substring(0, extendedTokenLabel.indexOf(';'));
                    final String tokenLabel = extendedTokenLabel.substring(extendedTokenLabel.indexOf(';') + 1);
                    if (!tokenLabel.isEmpty()) {
                        // Bravely assume that slots without a token label are not initialized or irrelevant
                        if (allowedSlots == null || allowedSlots.contains(slotId)) {
                            // Only show white-listed slots
                            ret.add(new SelectItem(tokenLabel, tokenLabel + " (index=" + index + ", id=" + slotId + ")"));
                        }
                    }
                    index++;
                }
            }
        } catch (Exception e) {
            log.info("Administrator " + authenticationToken.toString() + " tries to list PKCS#11 slots using token label for P11 library '" + currentCryptoToken.getP11Library() + "'. Failed with: ", e);
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "Unable to retrieve token labels.", ""));
        }
        return ret;
    }

    /**
     * @return alias if present otherwise the filename
     */
    public String getP11AttributeFileAlias(String p11AttributeFile) {
        if (p11AttributeFile == null || p11AttributeFile.length() == 0) {
            return "Default";
        }
        String ret = WebConfiguration.getAvailableP11AttributeFiles().get(p11AttributeFile);
        if (ret == null || ret.length() == 0) {
            ret = p11AttributeFile;
        }
        return ret;
    }

    /**
     * @return a list of usable CryptoToken types
     */
    public List<SelectItem> getAvailableCryptoTokenTypes() {
        final List<SelectItem> ret = new ArrayList<>();
        final Collection<AvailableCryptoToken> availableCryptoTokens = CryptoTokenFactory.instance().getAvailableCryptoTokens();
        for (AvailableCryptoToken availableCryptoToken : availableCryptoTokens) {
            if (availableCryptoToken.getClassPath().equals(NullCryptoToken.class.getName())) {
                // Special case: Never expose the NullCryptoToken when creating new tokens
                continue;
            }
            if (availableCryptoToken.getClassPath().equals(PKCS11CryptoToken.class.getName()) ||
                    availableCryptoToken.getClassPath().equals(CryptoTokenFactory.JACKNJI_NAME)) {
                // Never expose the PKCS11 or "PKCS11 NG" crypto tokens when creating new tokens if not enabled in web.properties
                if (availableCryptoToken.getClassPath().equals(PKCS11CryptoToken.class.getName()) && !WebConfiguration.isSunP11Enabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("SunP11 Crypto Token support is not enabled in GUI. See web.properties for enabling Sun PKCS#11.");
                    }
                    continue;
                }
                // Special case: Never expose the PKCS11CryptoToken when creating new tokens if no libraries are detected
                if (!isAnyP11LibraryAvailable()) {
                    if (log.isDebugEnabled()) {
                        log.debug("No known PKCS#11 libraries are available, not enabling PKCS#11 support in GUI. See web.properties for configuration of new PKCS#11 libraries.");
                    }
                    continue;
                }
            }
            if (availableCryptoToken.getClassPath().equals(AzureCryptoToken.class.getName())) {
                // Never expose the AzureCryptoToken when creating new tokens if it is not enabled in web.properties
                if (!WebConfiguration.isAzureKeyVaultEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Azure Key Vault Crypto Token support is not enabled in GUI. See web.properties for enabling Azure Key Vault.");
                    }
                    continue;
                }
            }
            if (availableCryptoToken.getClassPath().equals(CryptoTokenFactory.AWSKMS_NAME)) {
                // Never expose the AWSKMSCryptoToken when creating new tokens if it is not enabled in web.properties
                if (!WebConfiguration.isAWSKMSEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("AWS KMS Crypto Token support is not enabled in GUI. See web.properties for enabling AWS KMS.");
                    }
                    continue;
                }
            }
            if (availableCryptoToken.getClassPath().equals(CryptoTokenFactory.FORTANIX_NAME)) {
                // Don't expose the FortanixCryptoToken when creating new tokens if it is not enabled in web.properties
                if (!WebConfiguration.isFortanixEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Fortanix DSM Crypto Token support is not enabled in GUI. See web.properties for enabling Fortanix DSM.");
                    }
                    continue;
                }
            }
            if (availableCryptoToken.getClassPath().equals(CryptoTokenFactory.SECUROSYS_NAME)) {
                // Never expose the SecurosysCryptoToken when creating new tokens if it is not enabled in web.properties
                if (!WebConfiguration.isSecurosysPrimusHsmEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Securosys Primus HSM Crypto Token support is not enabled in GUI. See web.properties for enabling Securosys Primus HSM.");
                    }
                    continue;
                }
            }

            // Use one the class's simpleName
            final String fullClassName = availableCryptoToken.getClassPath();
            ret.add(new SelectItem(fullClassName.substring(fullClassName.lastIndexOf('.') + 1), availableCryptoToken.getName()));
        }
        return ret;
    }

    /**
     * Used to draw the back link. No white-listing to the calling method must be careful to only use this for branching.
     */
    public String getParamRef() {
        final String reference = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("ref");
        if (initNewPki) {
            return "initpki";
        } else if (reference == null || reference.isEmpty()) {
            return "default";
        }
        return reference;
    }

    /**
     * @return the id of the CryptoToken that is subject to view or edit
     */
    public int getCurrentCryptoTokenId() {
        // Get the HTTP GET/POST parameter named "cryptoTokenId"
        final String cryptoTokenIdString = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("cryptoTokenId");
        if (cryptoTokenIdString != null && cryptoTokenIdString.length() > 0) {
            try {
                int currentCryptoTokenId = Integer.parseInt(cryptoTokenIdString);
                // If there is a query parameter present and the id is different we flush the cache!
                if (currentCryptoTokenId != this.currentCryptoTokenId) {
                    flushCaches();
                    this.currentCryptoTokenId = currentCryptoTokenId;
                }
                // Always switch to edit mode for new ones and view mode for all others
                setCurrentCryptoTokenEditMode(currentCryptoTokenId == 0);
            } catch (NumberFormatException e) {
                log.info("Bad 'cryptoTokenId' parameter value.. set, but not a number..");
            }
        }
        return currentCryptoTokenId;
    }

    /**
     * @return cached or populate a new CryptoToken GUI representation for view or edit
     */
    public CurrentCryptoTokenGuiInfo getCurrentCryptoToken() throws AuthorizationDeniedException {
        if (this.currentCryptoToken == null) {
            final int cryptoTokenId = getCurrentCryptoTokenId();
            final CurrentCryptoTokenGuiInfo currentCryptoToken = new CurrentCryptoTokenGuiInfo();
            // If the id is non-zero we try to load an existing token
            if (cryptoTokenId != 0) {
                final CryptoTokenInfo cryptoTokenInfo = Optional.ofNullable(cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId))
                        .orElseThrow(() -> new RuntimeException("Could not load CryptoToken with cryptoTokenId " + cryptoTokenId));
                currentCryptoToken.setAllowExportPrivateKey(cryptoTokenInfo.isAllowExportPrivateKey());
                currentCryptoToken.setAutoActivate(cryptoTokenInfo.isAutoActivation());
                currentCryptoToken.setSecret1("");
                currentCryptoToken.setSecret2("");
                currentCryptoToken.setName(cryptoTokenInfo.getName());
                currentCryptoToken.setType(cryptoTokenInfo.getType());
                currentCryptoToken.setKeyPlaceholders(cryptoTokenInfo.getCryptoTokenProperties().getProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, ""));
                currentCryptoToken.setAllowExplicitParameters(cryptoTokenInfo.isAllowExplicitParameters());

                if (cryptoTokenInfo.getType().equals(PKCS11CryptoToken.class.getSimpleName()) ||
                        cryptoTokenInfo.getType().equals(CryptoTokenFactory.JACKNJI_SIMPLE_NAME)) {
                    currentCryptoToken.setP11AttributeFile(cryptoTokenInfo.getP11AttributeFile());
                    currentCryptoToken.setP11Library(cryptoTokenInfo.getP11Library());
                    currentCryptoToken.setP11Slot(cryptoTokenInfo.getP11Slot());
                    currentCryptoToken.setP11SlotLabelType(cryptoTokenInfo.getP11SlotLabelType());
                    // Extra capabilities not stored in the crypto token, but defined for this type of P11 crypto token
                    WebConfiguration.P11LibraryInfo libinfo = WebConfiguration.getAvailableP11LibraryToAliasMap().get(currentCryptoToken.getP11Library());
                    if (libinfo != null) {
                        currentCryptoToken.setCanGenerateKey(libinfo.isCanGenerateKey());
                        currentCryptoToken.setCanGenerateKeyMsg(libinfo.getCanGenerateKeyMsg());
                    }
                }
                if (cryptoTokenInfo.getType().equals(AzureCryptoToken.class.getSimpleName())) {
                    currentCryptoToken.setKeyVaultType(cryptoTokenInfo.getKeyVaultType());
                    currentCryptoToken.setKeyVaultName(cryptoTokenInfo.getKeyVaultName());
                    currentCryptoToken.setKeyVaultClientID(cryptoTokenInfo.getKeyVaultClientID());
                    currentCryptoToken.setAzureAuthenticationType(cryptoTokenInfo.getAzureAuthenticationType());
                    currentCryptoToken.setKeyVaultKeyBinding(cryptoTokenInfo.getKeyVaultKeyBinding());
                }
                if (cryptoTokenInfo.getType().equals(CryptoTokenFactory.AWSKMS_SIMPLE_NAME)) {
                    currentCryptoToken.setAWSKMSRegion(cryptoTokenInfo.getAWSKMSRegion());
                    currentCryptoToken.setAwsKmsAuthenticationType(cryptoTokenInfo.getAWSKMSAuthenticationType());
                    currentCryptoToken.setAWSKMSAccessKeyID(cryptoTokenInfo.getAWSKMSAccessKeyID());
                }
                if (cryptoTokenInfo.getType().equals(CryptoTokenFactory.FORTANIX_SIMPLE_NAME)) {
                    currentCryptoToken.setFortanixBaseAddress(cryptoTokenInfo.getFortanixBaseAddress());
                }
                if (cryptoTokenInfo.getType().equals(CryptoTokenFactory.SECUROSYS_SIMPLE_NAME)) {
                    currentCryptoToken.setSecurosysRestApi(cryptoTokenInfo.getSecurosysRestApiName());
                    currentCryptoToken.setSecurosysAuthenticationType(cryptoTokenInfo.getSecurosysAuthType());
                    currentCryptoToken.setSecurosysAuthCert(cryptoTokenInfo.getSecurosysAuthCert());
                    currentCryptoToken.setSecurosysManagementKey(cryptoTokenInfo.getSecurosysManagementKey());
                    currentCryptoToken.setSecurosysOperationKey(cryptoTokenInfo.getSecurosysOperationKey());
                    currentCryptoToken.setSecurosysServiceKey(cryptoTokenInfo.getSecurosysServiceKey());
                    currentCryptoToken.setSecurosysApprovalTimeout(cryptoTokenInfo.getSecurosysApprovalTimeout());
                }
                currentCryptoToken.setActive(cryptoTokenInfo.isActive());
                currentCryptoToken.setReferenced(getReferencedCryptoTokenIds().contains(cryptoTokenId));
            }
            this.currentCryptoToken = currentCryptoToken;
        }
        return this.currentCryptoToken;
    }

    public void selectCryptoTokenType() {
        // NOOP: Only for page reload
    }

    public void selectKeyVaultUseBinding() {
        // NOOP: Only for page reload
    }

    public void selectCryptoTokenLabelType() {
        // Clear slot reference when we change type
        currentCryptoToken.setP11Slot("");
    }

    public boolean isCurrentCryptoTokenEditMode() {
        return currentCryptoTokenEditMode;
    }

    public void setCurrentCryptoTokenEditMode(boolean currentCryptoTokenEditMode) {
        this.currentCryptoTokenEditMode = currentCryptoTokenEditMode;
    }

    public void toggleCurrentCryptoTokenEditMode() {
        currentCryptoTokenEditMode ^= true;
    }

    //
    // KeyPair related stuff
    //

    // This default is taken from CAToken.SOFTPRIVATESIGNKEYALIAS, but we don't want to depend on the CA module
    private String newKeyPairAlias = "signKey";
    private String newKeyPairSpec = AlgorithmConstants.KEYALGORITHM_RSA + "4096";

    /**
     * @return a List of available (but not necessarily supported by the underlying CryptoToken) key specs
     */
    public List<SelectItem> getAvailableKeySpecs() {
        final List<SelectItem> availableKeySpecs = new ArrayList<>();
        final int[] SIZES_RSA = { 1024, 1536, 2048, 3072, 4096, 6144, 8192 };
        for (int size : SIZES_RSA) {
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_RSA + size, AlgorithmConstants.KEYALGORITHM_RSA + " " + size));
        }
        final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap();
        final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
        Arrays.sort(keys);
        for (final String name : keys) {
            availableKeySpecs.add(new SelectItem(name, AlgorithmConstants.KEYALGORITHM_ECDSA + " " + StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(name))));
        }
        availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED25519, AlgorithmConstants.KEYALGORITHM_ED25519));
        availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED448, AlgorithmConstants.KEYALGORITHM_ED448));
        if (WebConfiguration.isPQCEnabled()) {
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_FALCON512, AlgorithmConstants.KEYALGORITHM_FALCON512));
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_FALCON1024, AlgorithmConstants.KEYALGORITHM_FALCON1024));
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_MLDSA44, AlgorithmConstants.KEYALGORITHM_MLDSA44));
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_MLDSA65, AlgorithmConstants.KEYALGORITHM_MLDSA65));
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_MLDSA87, AlgorithmConstants.KEYALGORITHM_MLDSA87));
        }
        return availableKeySpecs;
    }

    private String getEcKeySpecAliases(final String ecKeySpec) {
        StringBuilder ret = new StringBuilder();
        for (final String alias : AlgorithmTools.getEcKeySpecAliases(ecKeySpec)) {
            if (ret.length() != 0) {
                ret.append(" / ");
            }
            ret.append(alias);
        }
        return ret.toString();
    }

    /**
     * @return true if admin may generate keys in the current CryptoTokens.
     */
    public boolean isAllowedToKeyGeneration() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.GENERATE_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    /**
     * @return true if admin may test keys from the current CryptoTokens.
     */
    public boolean isAllowedToKeyTest() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.TEST_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    /**
     * @return true if admin may remove keys from the current CryptoTokens.
     */
    public boolean isAllowedToKeyRemoval() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.REMOVE_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    public boolean isKeyPairGuiListEmpty() throws AuthorizationDeniedException {
        return getKeyPairGuiList().getRowCount() == 0;
    }

    public boolean isKeyPairGuiListFailed() throws AuthorizationDeniedException {
        getKeyPairGuiList(); // ensure loaded
        return keyPairGuiListError != null;
    }

    public String getKeyPairGuiListError() throws AuthorizationDeniedException {
        getKeyPairGuiList(); // ensure loaded
        return keyPairGuiListError;
    }

    /**
     * @return a list of all the keys in the current CryptoToken.
     */
    public ListDataModel<KeyPairGuiInfo> getKeyPairGuiList() throws AuthorizationDeniedException {
        if (keyPairGuiList == null) {
            final List<KeyPairGuiInfo> ret = new ArrayList<>();
            if (getCurrentCryptoToken().isActive()) {
                // Add existing key pairs
                try {
                    final Properties tokenProperties = cryptoTokenManagementSession.getCryptoToken(getCurrentCryptoTokenId()).getProperties();
                    for (KeyPairInfo keyPairInfo : cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), getCurrentCryptoTokenId())) {
                        final KeyPairGuiInfo keyPairGuiInfo = new KeyPairGuiInfo(keyPairInfo);
                        // If CP5 HSM, add KAK association for each key
                        if (getCurrentCryptoToken().isShowAuthorizationInfo()) {
                            String kakProperties = tokenProperties.getProperty(CryptoToken.KAK_ASSOCIATION_PREFIX + keyPairInfo.getAlias());
                            if (kakProperties != null) {
                                // {cryptoTokenId, alias}
                                String[] kakAssociation = kakProperties.split(";");
                                keyPairGuiInfo.setSelectedKakCryptoTokenId(Integer.parseInt(kakAssociation[0]));
                                keyPairGuiInfo.setSelectedKakKeyAlias(kakAssociation[1]);
                            }
                        }
                        ret.add(keyPairGuiInfo);
                    }
                    keyPairGuiListError = null; // if we had an error last time we loaded but it has been fixed.
                } catch (CryptoTokenOfflineException ctoe) {
                    keyPairGuiListError = "Failed to load key pairs from CryptoToken: " + ctoe.getMessage();
                }
                // Add placeholders for key pairs
                Arrays.stream(getCurrentCryptoToken().getKeyPlaceholders().split("[" + CryptoToken.KEYPLACEHOLDERS_OUTER_SEPARATOR + "]"))
                        .filter(template -> !template.trim().isEmpty())
                        .forEach(template -> ret.add(new KeyPairGuiInfo(template)));
            }
            Collections.sort(ret, (keyPairInfo1, keyPairInfo2) -> keyPairInfo1.getAlias().compareTo(keyPairInfo2.getAlias()));
            keyPairGuiInfos = ret;
            keyPairGuiList = new ListDataModel<>(keyPairGuiInfos);
        }
        return keyPairGuiList;
    }


    public String getNewKeyPairSpec() {
        return newKeyPairSpec;
    }

    public void setNewKeyPairSpec(String newKeyPairSpec) {
        this.newKeyPairSpec = newKeyPairSpec;
    }

    public String getNewKeyPairAlias() {
        return newKeyPairAlias;
    }

    public void setNewKeyPairAlias(final String newKeyPairAlias) {
        this.newKeyPairAlias = StringUtils.strip(newKeyPairAlias);
    }

    /**
     * Invoked when admin requests a new key pair generation.
     *
     * @throws AuthorizationDeniedException
     */
    public void generateNewKeyPair() throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">generateNewKeyPair");
        }
        final KeyGenParamsBuilder keyGenParamsBuilder = KeyGenParams.builder(getNewKeyPairSpec());
        if (CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(getCurrentCryptoToken().getType())) {
            if (keyPairTemplate == null) {
                addErrorMessage("Key Usage not selected");
                return;
            }
            keyGenParamsBuilder.withKeyPairTemplate(keyPairTemplate);
        }
        try {
            cryptoTokenManagementSession.createKeyPair(getAdmin(), getCurrentCryptoTokenId(), getNewKeyPairAlias(), keyGenParamsBuilder.build());
        } catch (CryptoTokenOfflineException e) {
            final String msg = "Token is offline. Keypair cannot be generated. " + e.getMessage();
            log.debug(msg, e);
            addNonTranslatedErrorMessage(msg);
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
            final String logMsg = getAdmin().toString() + " failed to generate a keypair: ";
            log.info(logMsg + e.getMessage());
        }
        flushCaches();
        if (log.isTraceEnabled()) {
            log.trace("<generateNewKeyPair");
        }
    }

    /**
     * Invoked when admin requests key pair generation from a template placeholder
     */
    public void generateFromTemplate() {
        if (log.isTraceEnabled()) {
            log.trace(">generateFromTemplate");
        }
        String keyUsage = null;
        KeyPairTemplate template = null;
        final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        if (keyPairGuiInfo.getKeyUsage() != null) {
            keyUsage = keyPairGuiInfo.getKeyUsage().toString();
        }
        if (keyUsage != null && !keyUsage.equals("null")) {
            template = matchTemplate(keyUsage);
        }
        final String keyspec = keyPairGuiInfo.getRawKeySpec();
        try {
            cryptoTokenManagementSession.createKeyPairFromTemplate(getAdmin(), getCurrentCryptoTokenId(), alias, keyspec, template);
        } catch (CryptoTokenOfflineException e) {
            addNonTranslatedErrorMessage("Token is offline. Keypair cannot be generated.");
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);;
            final String logMsg = getAdmin().toString() + " failed to generate a keypair: ";
            log.info(logMsg + e.getMessage());
        }
        flushCaches();
        if (log.isTraceEnabled()) {
            log.trace("<generateFromTemplate");
        }
    }

    private KeyPairTemplate matchTemplate(String keyUsage) {
        if (keyUsage != null) {
            return KeyPairTemplate.valueOf(keyUsage);
        }
        return null;
    }

    /**
     * Invoked when admin associates KAK with HSM key (specific to CP5 HSMs)
     */
    public void initializeKey() {
        final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
        if (!keyPairGuiInfo.initialized) {
            final String alias = keyPairGuiInfo.getAlias();
            final String kakAlias = keyPairGuiInfo.getSelectedKakKeyAlias();
            final int kakTokenId = keyPairGuiInfo.getSelectedKakCryptoTokenId();
            if (kakTokenId == 0 || kakAlias == null) {
                addNonTranslatedErrorMessage("Key Authorization Key must be selected in order to initialize key.");
                return;
            }
            final String selectedPaddingScheme = keyPairGuiInfo.getSelectedPaddingScheme();
            if (selectedPaddingScheme == null) {
                addNonTranslatedErrorMessage("Signing algorithm was not chosen");
                return;
            }
            try {
                cryptoTokenManagementSession.keyAuthorizeInit(authenticationToken, getCurrentCryptoTokenId(), alias, kakTokenId, kakAlias, selectedPaddingScheme);
                keyPairGuiInfo.initialized = true;
                addNonTranslatedInfoMessage("Key '" + alias + "' initialized successfully.");
            } catch (CryptoTokenOfflineException | EJBException | CryptoTokenAuthenticationFailedException e) {
                addNonTranslatedErrorMessage(e);
                keyPairGuiInfo.initialized = false;
            }
        }
    }

    /**
     * Invoked when admin associates authorizes an with HSM key which has been associated with KAK (specific to CP5 HSMs)
     */
    public void authorizeKey() {
        authorizeInProgress = false;
        final KeyPairGuiInfo keyPairGuiInfo = currentKeyPairGuiInfo;
        final String alias = keyPairGuiInfo.getAlias();
        final String kakAlias = keyPairGuiInfo.getSelectedKakKeyAlias();
        final int kakTokenId = keyPairGuiInfo.getSelectedKakCryptoTokenId();
        if (kakTokenId == 0 || kakAlias == null) {
            addNonTranslatedErrorMessage("Key Authorization Key must be selected in order to authorize key.");
            return;
        }
        final String selectedPaddingScheme = keyPairGuiInfo.getSelectedPaddingScheme();
        if (selectedPaddingScheme == null) {
            addNonTranslatedErrorMessage("Signing algorithm was not chosen");
            return;
        }
        try {
            cryptoTokenManagementSession.keyAuthorize(authenticationToken, getCurrentCryptoTokenId(), alias, kakTokenId,
                    kakAlias, Long.parseLong(getMaxOperationCount()), selectedPaddingScheme);
            addNonTranslatedInfoMessage("Key '" + alias + "' authorized successfully.");
        } catch (CryptoTokenOfflineException | EJBException | CryptoTokenAuthenticationFailedException e) {
            addNonTranslatedErrorMessage(e);
        }
    }


    /**
     * Invoked when admin requests a test of a key pair.
     */
    public void testKeyPair() {
        final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        final String messageString = getKeyUsageInfoMessage(keyPairGuiInfo.getKeyUsage(), alias);
        try {
            cryptoTokenManagementSession.testKeyPair(getAdmin(), getCurrentCryptoTokenId(), alias);
            super.addNonTranslatedInfoMessage(messageString);
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
        }
    }

    /**
     * Provides additional GUI message info for testKeyPair()
     * @param keyUsage the key usage fetched from KeyPairGuiInfo
     * @param keyAlias the name/alias of the key (pair)
     * @return user friendly String with key usage for a key pair.
     */
    private String getKeyUsageInfoMessage(final String keyUsage, final String keyAlias) {
        String keyUsageInfoMessageString = "Keypair";
        if (keyAlias != null) {
            keyUsageInfoMessageString += " with alias " + keyAlias;
        }
        if (keyUsage != null && keyUsage.equals("ENCRYPT")) {
            keyUsageInfoMessageString += " tested successfully using encryption and decryption operations.";
        } else {
            keyUsageInfoMessageString += " tested successfully using signing and verification operations.";
        }
        return keyUsageInfoMessageString;
    }

    /**
     * Invoked when admin requests the removal of a key pair.
     */
    public void removeKeyPair() {
        final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        try {
            if (!keyPairGuiInfo.isPlaceholder()) {
                cryptoTokenManagementSession.removeKeyPair(getAdmin(), getCurrentCryptoTokenId(), alias);
            } else {
                cryptoTokenManagementSession.removeKeyPairPlaceholder(getAdmin(), getCurrentCryptoTokenId(), alias);
            }
            flushCaches();
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
        }
    }

    /**
     * Invoked when admin requests the removal of multiple key pair.
     */
    public void removeSelectedKeyPairs() {
        if (keyPairGuiInfos != null) {
            keyPairGuiInfos.stream().filter(KeyPairGuiInfo::isSelected).forEach(cryptoTokenKeyPairInfo -> {
                try {
                    if (!cryptoTokenKeyPairInfo.isPlaceholder()) {
                        cryptoTokenManagementSession.removeKeyPair(getAdmin(), getCurrentCryptoTokenId(), cryptoTokenKeyPairInfo.getAlias());
                    } else {
                        cryptoTokenManagementSession.removeKeyPairPlaceholder(getAdmin(), getCurrentCryptoTokenId(), cryptoTokenKeyPairInfo.getAlias());
                    }
                } catch (Exception e) {
                    addNonTranslatedErrorMessage(e);
                }
            });
        }
        flushCaches();
    }

    /**
     * @return A SlotList that contains the allowed slots numbers and indexes, or null if there's no such restriction
     */
    private SlotList getP11SlotList() {
        String library = currentCryptoToken.getP11Library();
        if (library == null) {
            return null;
        }
        WebConfiguration.P11LibraryInfo libinfo = WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
        if (libinfo == null) {
            return null;
        }
        return libinfo.getSlotList();
    }

    /**
     * @return true if we have checked and noticed that the P11 slot of the crypto token we try to create is the same as an already existing crypto token (including database protection tokens)
     */
    public boolean isP11SlotUsed() {
        return p11SlotUsed;
    }
}
