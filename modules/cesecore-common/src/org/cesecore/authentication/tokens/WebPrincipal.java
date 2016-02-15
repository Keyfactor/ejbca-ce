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

import java.io.Serializable;
import java.security.Principal;

/**
 * Represents any type of web user, can be public web or a servlet.
 * 
 * @version $Id$
 */
public class WebPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    final String moduleName;
    final String clientIPAddress;
    
    /**
     * @param moduleName Arbitrary identifier of the page or module, e.g. "AutoEnrollServlet"
     * @param clientIPAddress Remote IP address
     */
    public WebPrincipal(final String moduleName, final String clientIPAddress) {
        this.clientIPAddress = clientIPAddress;
        this.moduleName = moduleName;
    }
    
    @Override
    public String getName() {
        return clientIPAddress;
    }

    @Override
    public String toString() {
        return moduleName + ": " + clientIPAddress;
    }
    
    public String getModuleName() {
        return moduleName;
    }
    
    public String getClientIPAddress() {
        return clientIPAddress;
    }
}
