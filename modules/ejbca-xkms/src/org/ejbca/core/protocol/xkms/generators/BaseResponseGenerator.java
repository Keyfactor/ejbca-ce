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

package org.ejbca.core.protocol.xkms.generators;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;

/**
 * 
 * The most basic response generator that manages connections with EJBCA session
 * beans
 * 
 * @author Philip Vendil 2006 sep 27
 * 
 * @version $Id$
 */

public abstract class BaseResponseGenerator {

    @SuppressWarnings("unused")
    private static Logger log = Logger.getLogger(BaseResponseGenerator.class);

    protected AuthenticationToken raAdmin = null;
    protected AuthenticationToken pubAdmin = null;

    protected String remoteIP = null;

    public BaseResponseGenerator(String remoteIP) {
        this.remoteIP = remoteIP;
        raAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("XKMS RA: "+remoteIP));
        pubAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("XKMS USER: "+remoteIP));
        //raAdmin = new Admin(Admin.TYPE_RA_USER, remoteIP);
        //pubAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteIP);
    }

}
