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
package org.ejbca.core.ejb.unidfnr;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * 
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class UnidfnrProxySessionBean implements UnidfnrProxySessionRemote {

    private UnidfnrSessionLocal unidfnrSession = new EjbLocalHelper().getUnidfnrSession();

    @Override
    public void removeUnidFnrDataIfPresent(final String unid) {
        unidfnrSession.removeUnidFnrDataIfPresent(unid);
    }

    @Override
    public void storeUnidFnrData(final String unid, final String fnr) {
        unidfnrSession.storeUnidFnrData(unid, fnr);
    }
    
    @Override
    public String fetchUnidFnrDataFromMock(String serialNumber) {           
        //Utilize the fact that the mocked UnidFnrHandler uses a static volatile map 
        UnidFnrHandlerMock unidFnrHandlerMock = new UnidFnrHandlerMock();
        return unidFnrHandlerMock.fetchUnidFnrData(serialNumber);
    }
}
