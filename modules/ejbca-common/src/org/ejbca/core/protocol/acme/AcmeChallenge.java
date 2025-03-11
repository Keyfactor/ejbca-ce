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
import java.util.Map;
import java.util.TreeMap;

import org.ejbca.core.protocol.acme.AcmeIdentifier.AcmeIdentifierTypes;

/**
 * An ACME Challenge is a proof a client needs to provide in order to be authorized to get a certificate for an identifier.
 * 
 * PROCESSING constant in AcmeChallengeStatus ENUM is a requirement by 
 * <a href="https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6">RFC8555 ch. 7.1.6</a>, whereas the challenge retry 
 * by the ACME server is optional.
 *
 * Additionally, the challenge in the referenced draft `dns-account-01` is considered.
 * 
 * Includes <a href="https://www.rfc-editor.org/rfc/rfc8737.html">RFC8737 Automated Certificate Management Environment (ACME) IP Identifier Validation Extension</a>
 * Includes <a href="https://www.rfc-editor.org/rfc/rfc8738.html">RFC8738 Automated Certificate Management Environment (ACME) TLS Application‑Layer Protocol Negotiation (ALPN) Challenge Extension</a>
 * Includes <a href="https://datatracker.ietf.org/doc/draft-ietf-acme-dns-account-label/">DRAFT Automated Certificate Management Environment (ACME) DNS Labeled With ACME Account ID Challenge </a>
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
        DNS_DNS_ACCOUNT_01(AcmeIdentifierTypes.DNS, "dns-account-01"),
        DNS_TLS_ALPN_01(AcmeIdentifierTypes.DNS, "tls-alpn-01"),
        IP_HTTP_01(AcmeIdentifierTypes.IP, "http-01");

        private static final String REQUEST_V2_VALIDATION_METHOD_ACME_HTTP_01 = "acme-http-01";
        private static final String REQUEST_V2_VALIDATION_METHOD_ACME_DNS_01 = "acme-dns-01";
        
        private static final Map<String,String> CHALLENGE_TO_MPIC_CHALLENGE_MAPPING = new TreeMap<>();
        
        static {
            CHALLENGE_TO_MPIC_CHALLENGE_MAPPING.put(DNS_HTTP_01.getChallengeType(), REQUEST_V2_VALIDATION_METHOD_ACME_HTTP_01);
            CHALLENGE_TO_MPIC_CHALLENGE_MAPPING.put(DNS_DNS_01.getChallengeType(), REQUEST_V2_VALIDATION_METHOD_ACME_DNS_01);
        }
        
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
        
        /**
         * Returns true if the challenge type is dns-http-01 or ip-http-01.
         * 
         * @param type the challenge type as a string.
         * @return true if the challenge is an HTTP challenge.
         */
        public static boolean isHttpChallenge(final String type) {
            return DNS_HTTP_01.getChallengeType().equals(type) || IP_HTTP_01.getChallengeType().equals(type);
        }
        
        /**
         * Returns true if the challenge type is dns-http-01 or dns-dns-01 or tls-alpn-01.
         * 
         * @param type the challenge type as a string.
         * @return true if the challenge is an HTTP challenge.
         */
        public static boolean isMpicChallenge(final String type) {
            return DNS_HTTP_01.getChallengeType().equals(type) || DNS_DNS_01.getChallengeType().equals(type);
        }
        
        public static String getMpicChallengeType(String challengeName) {
            return CHALLENGE_TO_MPIC_CHALLENGE_MAPPING.get(challengeName);
        }
    }
}