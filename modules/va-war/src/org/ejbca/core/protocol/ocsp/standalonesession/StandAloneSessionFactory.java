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

package org.ejbca.core.protocol.ocsp.standalonesession;

import javax.servlet.ServletException;

import org.ejbca.core.protocol.ocsp.OCSPData;
import org.ejbca.ui.web.protocol.OCSPServletStandAlone.IStandAloneSession;

/**
 * Factory used to create the session.
 * 
 * @author primelars
 * @version  $Id$
 * 
 */
public class StandAloneSessionFactory {
    private static IStandAloneSession instance;
    /**
     * @param ocspServletStandAlone
     * @return The session
     * @throws ServletException
     */
    public static IStandAloneSession getInstance(OCSPData data) throws ServletException {
        if ( instance==null ) {
            instance = new StandAloneSession(data);
        }
        return instance;
    }
}
