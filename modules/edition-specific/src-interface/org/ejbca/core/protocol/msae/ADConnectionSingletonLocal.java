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

package org.ejbca.core.protocol.msae;

import javax.ejb.Local;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

@Local
public interface ADConnectionSingletonLocal {

    public void updateConnectionProperties();
    
    //TODO Will be covered in ECA-9766
//    public MSAutoEnrollmentSettingsTemplate getMsCertificateTemplates(String domain);
    
    public NamingEnumeration<SearchResult> getEntryNamedContext(String searchBase, String searchFilter, SearchControls searchCtls, String domain) 
            throws NamingException;
}
