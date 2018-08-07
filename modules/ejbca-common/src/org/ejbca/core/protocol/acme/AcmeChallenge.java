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

import java.util.LinkedHashMap;

/**
 * An ACME Challenge is a proof a client needs to provide in order to be authorized to get a certificate for an identifier.
 * 
 * PROCESSING constant in AcmeChallengeStatus ENUM is a requirement imposed by draft-ietf-acme-acme-12 and is preserved for
 * future use. 
 * 
 * @version $Id$
 */
public interface AcmeChallenge {

    String getChallengeId();

    void setChallengeId(String challengeId);

    String getType();

    void setType(String type);

    String getUrl();

    void setUrl(String url);

    AcmeChallengeStatus getStatus();

    void setStatus(AcmeChallengeStatus status);

    String getValidated();

    void setValidated(String validated);

    String getToken();

    void setToken(String token);

    String getKeyAuthorization();

    void setKeyAuthorization(String keyAuthorization);

    float getLatestVersion();

    void upgrade();
    
    LinkedHashMap<Object, Object> getRawData();

}