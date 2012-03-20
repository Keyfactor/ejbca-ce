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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.ui.web.pub.cluster.ValidationAuthorityHealthCheck;

/**
 * Currently a placeholder for the HealthCheck functionality which was extracted from OCSPStandAlone
 * 
 * TODO: Implement meeeeeeee!
 * 
 * @version $Id$
 *
 */
public class HealthCheckServlet extends HttpServlet implements IHealtChecker {

    private static final long serialVersionUID = -3256717200117000894L;

    /** Special logger only used to log version number. ejbca.version.log can be directed to a special logger, or have a special log level 
     * in the log4j configuration. 
     */
    private static final Logger m_versionLog = Logger.getLogger("org.ejbca.version.log");

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig config) throws ServletException {

        // Log with warn priority so it will be visible in strict production configurations  
        m_versionLog.warn("Init, " + GlobalConfiguration.EJBCA_VERSION + " OCSP startup");

        // session must be created before health check could be done
        ValidationAuthorityHealthCheck.setHealtChecker(this);
    }

    @Override
    public String healthCheck(boolean doSignTest, boolean doValidityTest) {
        // TODO Auto-generated method stub
        return null;
    }

}
