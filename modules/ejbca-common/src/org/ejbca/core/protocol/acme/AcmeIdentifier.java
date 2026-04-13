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

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Enumeration of ACME identifiers a client requests the CA to certify:
 * 
 * 1. DNS name (RFC8555) 
 * 2. IP  (RFC8738)
 * 3. permanentIdentifier OID 1.3.6.1.5.5.7.8.3 (draft-ietf-acme-device-attest-02)
 * 4. hardwareModuleName  OID 1.3.6.1.5.5.7.8.4 (draft-ietf-acme-device-attest-02)
*/
public interface AcmeIdentifier {
    
    String getType();

    void setType(String type);

    String getValue();

    void setValue(String value);

    enum AcmeIdentifierTypes {
        DNS("dns", false),
        IP("ip", false),
        PERMANENT_IDENTIFIER("permanent-identifier", true),
        HARDWARE_MODULE("hardware-module", true);

        private final String jsonValue;
        private final boolean isDeviceAttestation;

        AcmeIdentifierTypes(String jsonValue, boolean isDeviceAttestation) {
            this.jsonValue = jsonValue;
            this.isDeviceAttestation = isDeviceAttestation;
        }

        public String getJsonValue() {
            return jsonValue;
        }

        public boolean isDeviceAttestation() {
            return isDeviceAttestation;
        }

        private static final Map<String, AcmeIdentifierTypes> BY_JSON_VALUE =
                Arrays.stream(values())
                        .collect(Collectors.toMap(AcmeIdentifierTypes::getJsonValue, Function.identity()));

        public static AcmeIdentifierTypes fromJsonValue(String jsonValue) {
            AcmeIdentifierTypes type = BY_JSON_VALUE.get(jsonValue);
            if (type == null) {
                throw new IllegalArgumentException("Unknown acme identifier type: " + jsonValue);
            }
            return type;
        }
    }

    /**
     * Checks if the ACME identifier is used for device attestation, either PERMANENT_IDENTIFIER or HARDWARE_MODULE.
     *
     * @param identifier the identifier.
     * @return true if valid.
     */
    static boolean isDeviceAttestationIdentifier(final AcmeIdentifier identifier) {
        return AcmeIdentifierTypes.fromJsonValue(identifier.getType()).isDeviceAttestation();
    }

}