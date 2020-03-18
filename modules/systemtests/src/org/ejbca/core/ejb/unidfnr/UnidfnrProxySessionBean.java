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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UnidfnrSessionProxyRemote")
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
