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
package org.cesecore.authentication.tokens;

/**
 * Represents a public web user.  
 * 
 * @version $Id$
 */
public class PublicWebPrincipal extends WebPrincipal {

    private static final long serialVersionUID = 1L;

    public PublicWebPrincipal(final String clientIPAddress) {
        this("Public Web", clientIPAddress);
    }
    
    public PublicWebPrincipal(final String moduleName, final String clientIPAddress) {
        super(moduleName, clientIPAddress);
    }
}
