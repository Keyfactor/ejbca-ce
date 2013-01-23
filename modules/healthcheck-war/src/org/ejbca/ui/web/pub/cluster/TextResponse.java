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

package org.ejbca.ui.web.pub.cluster;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class that responds with a text string of status is OK else it responds the error message (optional).
 * 
 * Supports dynamic re-configuration via Commons Configuration.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class TextResponse implements IHealthResponse {

    private static final Logger log = Logger.getLogger(TextResponse.class);

    @Override
    public void respond(String status, HttpServletResponse resp) {
        resp.setContentType("text/plain");
        try {
            final Writer out = resp.getWriter();
            if (status == null) {
                // Return ok message
                out.write(EjbcaConfiguration.getOkMessage());
            } else {
            	// Check if we return a static error message or the more informative
            	final String customErrorMessage = EjbcaConfiguration.getCustomErrorMessage();
                if (customErrorMessage != null) {
                    status = customErrorMessage;
                }
                // Return fail message
                if (EjbcaConfiguration.getSendServerError()) {
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, status);
                } else {
                    out.write(status);
                }
            }
            out.flush();
            out.close();
        } catch (IOException e) {
            log.error("Error writing to Servlet Response.", e);
        }
    }
}
