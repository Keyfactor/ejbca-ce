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
 
package se.anatom.ejbca.admin;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.naming.*;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.util.CertTools;


/**
 * List certificates that will expire within the given number of days.
 *
 * @version $Id: CaListExpiredCommand.java,v 1.12 2005-02-11 13:12:18 anatom Exp $
 */
public class CaListExpiredCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaListExpiredCommand
     *
     * @param args command line arguments
     */
    public CaListExpiredCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
            String msg = "List certificates that will expire within the given number of days.\n";
            msg += "Usage: CA listexpired <days>";
            throw new IllegalAdminCommandException(msg);
        }

        try {
            long days = Long.parseLong(args[1]);
            Date findDate = new Date();
            long millis = (days * 24 * 60 * 60 * 1000);
            findDate.setTime(findDate.getTime() + (long) millis);
            getOutputStream().println("Looking for certificates that expire before " + findDate + ".");

            Collection certs = getExpiredCerts(findDate);
            Iterator iter = certs.iterator();

            while (iter.hasNext()) {
                X509Certificate xcert = (X509Certificate) iter.next();
                Date retDate = xcert.getNotAfter();
                String subjectDN = CertTools.getSubjectDN(xcert);
                String serNo = xcert.getSerialNumber().toString();
                getOutputStream().println("Certificate with subjectDN '" + subjectDN +
                    "' and serialNumber '" + serNo + "' expires at " + retDate + ".");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
    private Collection getExpiredCerts(Date findDate) {
        try {
            Context ctx = getInitialContext();
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup(
                        "CertificateStoreSession"), ICertificateStoreSessionHome.class);
            ;

            ICertificateStoreSessionRemote store = storehome.create();
            debug("Looking for cert with expireDate=" + findDate);

            Collection certs = store.findCertificatesByExpireTime(administrator, findDate);
            debug("Found " + certs.size() + " certs.");

            return certs;
        } catch (Exception e) {
            error("Error getting list of certificates", e);
        }

        return null;
    }

    // getExpiredCerts
}
