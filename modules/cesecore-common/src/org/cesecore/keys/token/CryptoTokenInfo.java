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

import java.io.Serializable;
import java.util.Properties;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

import org.cesecore.util.Named;

/**
 * Non-sensitive information about a CryptoToken.
 *
 */
public class CryptoTokenInfo implements Named, Serializable {

    private static final long serialVersionUID = 5025517840531557857L;
    private final Integer cryptoTokenId;
    private final String name;
    private final boolean active;
    private final boolean autoActivation;
    private final String type;
    private final Properties cryptoTokenProperties;

    public CryptoTokenInfo(Integer cryptoTokenId, String name, boolean active, boolean autoActivation, Class<? extends CryptoToken> type, Properties cryptoTokenProperties) {
        this.cryptoTokenId = cryptoTokenId;
        this.name = name;
        this.active = active;
        this.autoActivation = autoActivation;
        this.type = type.getSimpleName();
        this.cryptoTokenProperties = cryptoTokenProperties;
    }

    public Integer getCryptoTokenId() {
        return cryptoTokenId;
    }

    @Override
    public String getName() {
        return name;
    }

    public boolean isActive() {
        return active;
    }

    public boolean isAutoActivation() {
        return autoActivation;
    }

    public String getType() {
        return type;
    }

    public boolean isAllowExportPrivateKey() {
        return Boolean.valueOf(cryptoTokenProperties.getProperty(SoftCryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.FALSE.toString()));
    }

    public boolean isAllowExplicitParameters() {
        return Boolean.valueOf(cryptoTokenProperties.getProperty(SoftCryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS, Boolean.FALSE.toString()));
    }

    public String getP11Library() {
        return cryptoTokenProperties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, "");
    }

    public String getP11Slot() {
        return cryptoTokenProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE);
    }

    public String getP11SlotLabelType() {
        Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(cryptoTokenProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        if (slotLabelType != null) {
            return slotLabelType.getKey();
        } else {
            return null;
        }
    }

    public String getP11SlotLabelTypeDescription() {
        Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(cryptoTokenProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        if (slotLabelType != null) {
            return slotLabelType.getDescription();
        } else {
            return null;
        }
    }

    public String getP11AttributeFile() {
        return cryptoTokenProperties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, "");
    }

    public String getKeyVaultType() {
        return cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_TYPE);
    }
    public String getKeyVaultName() {
        return cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_NAME);
    }
    public String getKeyVaultClientID() {
        return cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_CLIENTID);
    }
    public String getKeyVaultKeyBinding() {
        return cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_KEY_BINDING);
    }

    public String getSecurosysRestApiName() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_REST_API);
    }

    public String getSecurosysAuthType() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_AUTHENTICATION_TYPE);
    }

    public String getSecurosysAuthCert() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_AUTH_CERT);
    }

    public String getSecurosysManagementKey() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_MANAGEMENT_KEY);
    }

    public String getSecurosysOperationKey() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_OPERATION_KEY);
    }

    public String getSecurosysServiceKey() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_SERVICE_KEY);
    }

    public String getSecurosysApprovalTimeout() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.SECUROSYS_APPROVAL_TIMEOUT);
    }

    public String getAWSKMSRegion() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.AWSKMS_REGION);
    }

    public AwsKmsAuthenticationType getAWSKMSAuthenticationType() {
        String authenticationTypeString = cryptoTokenProperties.getProperty(CryptoTokenConstants.AWSKMS_AUTHENTICATION_TYPE);
        return authenticationTypeString == null ? AwsKmsAuthenticationType.KEY_ID_AND_SECRET
                : AwsKmsAuthenticationType.valueOf(authenticationTypeString);
    }

    public String getAWSKMSAccessKeyID() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.AWSKMS_ACCESSKEYID);
    }
    public Properties getCryptoTokenProperties() {
        return cryptoTokenProperties;
    }
    public String getFortanixBaseAddress() {
        return cryptoTokenProperties.getProperty(CryptoTokenConstants.FORTANIX_BASE_ADDRESS);
    }

    public AzureAuthenticationType getAzureAuthenticationType() {
        // legacy setting
        if (Boolean.parseBoolean(cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_USE_KEY_BINDING, "false"))) {
            return AzureAuthenticationType.KEY_BINDING;
        }
        final String authenticationTypeString = cryptoTokenProperties.getProperty(AzureCryptoToken.KEY_VAULT_AUTHENTICATION_TYPE);
        return authenticationTypeString == null ? AzureAuthenticationType.APP_ID_AND_SECRET : AzureAuthenticationType.valueOf(authenticationTypeString);
    }

    /**
     * False if this is an Azure Key Vault Token using key binding or managed identity authentication
     * or a AWS KMS Key Vault Token using service credentials.
     */
    public boolean requiresSecretToActivate() {
        if (getType().equals(AzureCryptoToken.class.getSimpleName()) && getAzureAuthenticationType() != AzureAuthenticationType.APP_ID_AND_SECRET) {
            return false;
        }
        if (getType().equals(CryptoTokenFactory.AWSKMS_SIMPLE_NAME) && getAWSKMSAuthenticationType() != AwsKmsAuthenticationType.KEY_ID_AND_SECRET) {
            return false;
        }
        return true;
    }
}
