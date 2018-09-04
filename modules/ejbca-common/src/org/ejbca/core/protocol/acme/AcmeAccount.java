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

package org.ejbca.core.protocol.acme;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;

import org.cesecore.internal.IUpgradeableData;

/**
 * Interface for AcmeAccount implementations
 * 
 * @version $Id$
 *
 */

public interface AcmeAccount extends Serializable, IUpgradeableData {

    String URL_PROTOCOL_MAILTO_START = "mailto:";

    PublicKey getPublicKey();

    void setPublicKey(PublicKey publicKey);

    String getAccountId();

    void setAccountId(String accountId);

    /** The status of this account. Possible values are: "valid", "deactivated", and "revoked". ...*/
    String getStatus();

    void setStatus(String status);

    List<String> getContact();

    void setContact(List<String> contact);

    String getExternalAccountBinding();

    void setExternalAccountBinding(String externalAccountBinding);

    /** @return the version of Terms Of Service that the account holder has agreed to */
    String getTermsOfServiceAgreedVersion();

    void setTermsOfServiceAgreedVersion(String termsOfServiceAgreedVersion);

    String getConfigurationId();

    /** @return the configurationId of this account  */
    void setConfigurationId(String configurationId);

    /** @return the first email address registered under this account or null if none exists (which should not happen since we require one) 
     * @throws AcmeProblemException */
    String getContactEmail() throws AcmeProblemException;

    float getLatestVersion();

    void upgrade();

    LinkedHashMap<Object, Object> getRawData();
}
