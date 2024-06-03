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

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;

/**
 * 
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCrlStoreSessionBean implements InternalCrlStoreSessionRemote {

    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    @Override
    public void removeCrl(final String issuerDN) {
        crlStoreSession.removeByIssuerDN(issuerDN);
    }
}
