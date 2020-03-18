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

import javax.ejb.Local;

/**
 * 
 * @version $Id$
 *
 */
@Local
public interface UnidfnrSessionLocal extends UnidfnrSession {
    
    /**
     * @param unid unique id to store in unid fnr database
     * @param fnr actual fnr to store in the database
     */
    void storeUnidFnrData(final String unid, final String fnr);
    
    
    /**
     * Look up database and search for UnidFnrData object based on serial number
     * @param serialNumber unique serial number of unid fnr row in table.
     * @return The fnr with serialNumber as id if a mapping found in db otherwise null
     */
    String fetchUnidFnrData(final String serialNumber);
    
    /**
     * This method is used by ProtocolLookupServerHttpTest
     * @param unid id of the object to remove from UnidFnrData table
     * 
     */
    void removeUnidFnrDataIfPresent(final String unid);

}
