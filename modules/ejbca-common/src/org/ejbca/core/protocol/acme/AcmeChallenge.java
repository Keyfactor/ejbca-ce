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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.ejbca.core.protocol.acme.AcmeIdentifier.AcmeIdentifierTypes;

/**
 * An ACME Challenge is a proof a client needs to provide in order to be authorized to get a certificate for an identifier.
 * 
 * PROCESSING constant in AcmeChallengeStatus ENUM is a requirement imposed by draft-ietf-acme-acme-12 and is preserved for
 * future use.
 * 
 * Includes RFC8738 Automated Certificate Management Environment (ACME) IP Identifier Validation Extension
 */
public interface AcmeChallenge {

    String getChallengeId();

    void setChallengeId(String challengeId);

    String getAuthorizationId();

    void setAuthorizationId(String authorizationId);

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

    enum AcmeChallengeType {

        DNS_HTTP_01(AcmeIdentifierTypes.DNS, "http-01"),
        DNS_DNS_01(AcmeIdentifierTypes.DNS, "dns-01"),
        IP_HTTP_01(AcmeIdentifierTypes.IP, "http-01");

        private final AcmeIdentifierTypes acmeIdentifierType;
        private final String challengeType;

        AcmeChallengeType(final AcmeIdentifierTypes acmeIdentifierType, final String challengeType) {
            this.acmeIdentifierType = acmeIdentifierType;
            this.challengeType = challengeType;
        }

        public AcmeIdentifierTypes getAcmeIdentifierType() { return acmeIdentifierType; }
        public String getChallengeType() { return challengeType; }
        
        public static List<String> getDnsIdentifierChallengeTypes(AcmeIdentifier.AcmeIdentifierTypes identifierType) {
            final List<String> result = new ArrayList<>();
            for (AcmeChallengeType type : AcmeChallenge.AcmeChallengeType.values()) {
                if(identifierType.equals(type.getAcmeIdentifierType())) {
                    result.add(type.getChallengeType());
                }
            }
            return result;
        } 
    }
}