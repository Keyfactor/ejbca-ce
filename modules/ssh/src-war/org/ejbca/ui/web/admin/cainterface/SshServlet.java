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
package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import java.security.PublicKey;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.util.StringTools;
import org.ejbca.ui.web.RequestHelper;

/**
 * Servlet used to distribute CA keys in SSH format.
 *
 * @version $Id$
 */
public class SshServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(SshServlet.class);

    public static final String NAME_PROPERTY = "name";

    @EJB
    private CaSessionLocal caSession;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    	if (caSession==null) {
    		log.error("Local EJB injection failed.");
    	}
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost() SshServlet");
        doGet(req, res);
        log.trace("<doPost() SshServlet");
    }

    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet() SshServlet");
        RequestHelper.setDefaultCharacterEncoding(req);
        if (log.isDebugEnabled()) {
            log.debug("Got request from " + req.getRemoteAddr());
        }
        final String caName = req.getParameter(NAME_PROPERTY);
        CAInfo caInfo = caSession.getCAInfoInternal(-1, caName, true);
        if(caInfo == null) {
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "No CA of name '" + caName + "' found.");
        } else if (caInfo.getCAType() != SshCaInfo.CATYPE_SSH){
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "CA of name '" + caName + "' not an SSH CA.");
        } else {
            final String fileName = caName + ".pub";
            PublicKey publicKey = caInfo.getCertificateChain().get(0).getPublicKey();
            String out = new String(SshKeyFactory.INSTANCE.getSshPublicKey(publicKey).encodeForExport(caName));
            res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(fileName) + "\"");
            res.setContentType("application/octet-stream");
            res.setContentLength(out.length());
            res.getOutputStream().write(out.getBytes());
            if (log.isDebugEnabled()) {
                log.debug("Sent CA Public Key to client in SSH format, len=" + out.length() + ".");
            }
        }
        log.trace("<doGet() SshServlet");
    }
}
