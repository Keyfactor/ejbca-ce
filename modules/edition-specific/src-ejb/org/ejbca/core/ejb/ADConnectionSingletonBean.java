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

import javax.ejb.DependsOn;
import javax.ejb.Singleton;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.ejbca.core.protocol.msae.ADConnectionSingletonLocal;

/**
 * Not available in Community Edition
 */
@Singleton
@DependsOn({"StartupSingletonBean"})
public class ADConnectionSingletonBean implements ADConnectionSingletonLocal {

    @Override
    public void updateConnectionProperties() {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }

    @Override
    public NamingEnumeration<SearchResult> getEntryNamedContext(String searchBase, String searchFilter, SearchControls searchCtls, String domain)
            throws NamingException {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }

}
