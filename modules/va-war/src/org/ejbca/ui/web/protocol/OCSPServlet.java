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

package org.ejbca.ui.web.protocol;

import javax.ejb.EJB;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.integrated.IntegratedOcspResponseGeneratorSessionLocal;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 *
 * @version  $Id$
 */
public class OCSPServlet extends BaseOcspServlet {

    private static final long serialVersionUID = 8081630219584820112L;
    private static final Logger log = Logger.getLogger(OCSPServlet.class);
    

    @EJB
    private IntegratedOcspResponseGeneratorSessionLocal integratedOcspResponseGeneratorSession;

    @Override
    public Logger getLogger() {
        return log;
    }

    @Override
    protected OcspResponseGeneratorSessionLocal getOcspResponseGenerator() {
        return integratedOcspResponseGeneratorSession;
    }

    
   
}
