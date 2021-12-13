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
package org.ejbca.core.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.core.protocol.acme.AcmeConfigurationSessionLocal;
import org.ejbca.core.protocol.acme.AcmeProblemException;

/**
 * ACME configuration handling business logic.
 *
 * Not available in Community Edition
 */
@Stateless
// We can't rely on transactions for calls that will do persistence over the RaMasterApi, so avoid the overhead of when methods are invoked
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeConfigurationSessionBean implements AcmeConfigurationSessionLocal {

    @Override
    public AcmeConfiguration getAcmeConfiguration(final AuthenticationToken authenticationToken, final String configurationAlias)
            throws AcmeProblemException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String parseAcmeEabMessage(AuthenticationToken authenticationToken, String alias, String requestUrl, String requestJwk,
            String eabRequestJsonString) throws AcmeProblemException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
 
}
