/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.util.HashMap;
import java.util.Map;

import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.ejbca.core.protocol.unid.UnidFnrHandler;

/**
 * This is a functional mock of UnidFnrHandler to be used in system tests. It's essential that it does nothing different than the original, 
 * the only difference being that instead of writing to persistence it writes all data to a mocked static value.
 * 
 * @version $Id$
 *
 */
public class UnidFnrHandlerMock extends UnidFnrHandler implements ExtendedUserDataHandler {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public UnidFnrHandlerMock() {
        super();
        super.unidfnrSession = new UnidFnrSessionMock();
    }
    
    public String fetchUnidFnrData(String serialNumber) {           
        return unidfnrSession.fetchUnidFnrData(serialNumber);
    }
    
    /**
     * Mock implementation of the session bean containing a static volatile hashmap.
     *
     */
    private static class UnidFnrSessionMock implements UnidfnrSessionLocal {
        
        private static volatile Map<String, String> storage = new HashMap<>();

        @Override
        public void storeUnidFnrData(String unid, String fnr) {
            storage.put(unid, fnr);       
        }

        @Override
        public String fetchUnidFnrData(String serialNumber) {           
            return storage.get(serialNumber);
        }

        @Override
        public void removeUnidFnrDataIfPresent(String unid) {
            storage.remove(unid);
        }
        
    }

}
