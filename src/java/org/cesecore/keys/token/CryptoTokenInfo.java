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

import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

/**
 * Non-sensitive information about a CryptoToken.
 * 
 * @version $Id$
 */
public class CryptoTokenInfo implements Serializable {

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
        return Boolean.valueOf(cryptoTokenProperties.getProperty(SoftCryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, ""));
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

    public Properties getCryptoTokenProperties() {
        return cryptoTokenProperties;
    }
}
