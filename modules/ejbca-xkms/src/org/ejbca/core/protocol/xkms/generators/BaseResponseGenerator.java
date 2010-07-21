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

package org.ejbca.core.protocol.xkms.generators;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;

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

    protected Admin raAdmin = null;
    protected Admin pubAdmin = null;

    protected String remoteIP = null;

    public BaseResponseGenerator(String remoteIP) {
        this.remoteIP = remoteIP;
        raAdmin = new Admin(Admin.TYPE_RA_USER, remoteIP);
        pubAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteIP);
    }

}
