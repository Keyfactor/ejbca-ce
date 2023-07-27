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
package org.cesecore.certificates.certificate;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.jndi.JndiConstants;

/**
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCrlStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCrlStoreSessionBean implements InternalCrlStoreSessionRemote {

    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    @Override
    public void removeCrl(final String issuerDN) {
        crlStoreSession.removeByIssuerDN(issuerDN);
    }
}
