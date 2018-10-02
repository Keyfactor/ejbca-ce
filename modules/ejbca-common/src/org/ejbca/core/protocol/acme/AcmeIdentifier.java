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

/**
 * An ACME identifier is what the client requests the CA to certify.
 * Only the type DNS name exists so far (RFC draft 06).
 * 
 * @version $Id$
 */
public interface AcmeIdentifier {
    
    String getType();

    void setType(String type);

    String getValue();

    void setValue(String value);

    enum AcmeIdentifierTypes {
        DNS;

        public String getJsonValue() { return this.name().toLowerCase(); }
    }
}