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

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class that responds with a text string of status is OK else it responds the error message (optional).
 * 
 * The following servlet init parameters might be used: OKMessage : the string to return when everything is ok. SendServerError : (boolean) Send A 500
 * Server error is returned instead of errormessage CustomErrorMsg : Send a static predefined errormessage instead of the on created by the
 * healthchecker.
 * 
 * @author Philip Vendil
 * @version $Id$
 * 
 */
public class TextResponse implements IHealthResponse {

    private static Logger log = Logger.getLogger(TextResponse.class);

    private static final String OK_MESSAGE = "ALLOK";

    private String okMessage = null;
    /* Parameter saying if a errorcode 500 should be sent in case of error. */
    private boolean sendServerError = true;
    private String customErrorMessage = null;

    public void init(ServletConfig config) {
        okMessage = EjbcaConfiguration.getOkMessage();
        if (okMessage == null) {
            okMessage = OK_MESSAGE;
        }
        sendServerError = EjbcaConfiguration.getSendServerError();
        
        customErrorMessage = EjbcaConfiguration.getCustomErrorMessage();
    }

    public void respond(String status, HttpServletResponse resp) {
        resp.setContentType("text/plain");
        try {
            Writer out = resp.getWriter();
            if (status == null) {
                // Return "EJBCAOK" Message
                out.write(okMessage);
            } else {
                // Return failinfo
                if (sendServerError) {
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, status);
                } else {
                    if (customErrorMessage != null) {
                        out.write(customErrorMessage);
                    } else {
                        out.write(status);
                    }
                }
            }
            out.flush();
            out.close();
        } catch (IOException e) {
            log.error("Error writing to Servlet Response.", e);
        }

    }

}
