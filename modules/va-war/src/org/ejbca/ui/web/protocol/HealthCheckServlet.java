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

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.ui.web.pub.cluster.ValidationAuthorityHealthCheck;

/**
 * Currently a placeholder for the HealthCheck functionality which was extracted from OCSPStandAlone
 * 
 * TODO: Implement meeeeeeee!
 * 
 * See ECA-2630
 * 
 * @version $Id$
 *
 */
public class HealthCheckServlet extends HttpServlet implements IHealtChecker {

    private static final long serialVersionUID = -3256717200117000894L;

    private static final Logger log = Logger.getLogger(HealthCheckServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private StandaloneOcspResponseGeneratorSessionLocal standaloneOcspResponseGeneratorSession;
    
    @Override
    public void init(ServletConfig config) throws ServletException {

        // session must be created before health check could be done
        ValidationAuthorityHealthCheck.setHealtChecker(this);
    }

    @Override
    public String healthCheck(boolean doSignTest, boolean doValidityTest) {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        try {
            //TODO: Not implemented yet. See  ECA-2630
        
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            log.error(errMsg, e);
            pw.print(errMsg + ": "+e.getMessage());
        }
        pw.flush();
        return sw.toString();
    }

}
