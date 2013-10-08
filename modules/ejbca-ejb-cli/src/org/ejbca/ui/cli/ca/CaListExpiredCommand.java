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
 
package org.ejbca.ui.cli.ca;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * List certificates that will expire within the given number of days.
 *
 * @version $Id$
 */
public class CaListExpiredCommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "listexpired"; }
    @Override
    public String getDescription() { return "List certificates that will expire within the given number of days"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <days>");
            return;
        }
        CryptoProviderTools.installBCProvider();
        try {
            long days = Long.parseLong(args[1]);
            Date findDate = new Date();
            long millis = (days * 24 * 60 * 60 * 1000);
            findDate.setTime(findDate.getTime() +  millis);
            getLogger().info("Looking for certificates that expire before " + findDate + ".");

            Collection<Certificate> certs = getExpiredCerts(findDate);
            Iterator<Certificate> iter = certs.iterator();

            while (iter.hasNext()) {
                Certificate cert = iter.next();
                Date retDate;
                if (cert instanceof CardVerifiableCertificate) {
                    retDate = ((CardVerifiableCertificate)cert).getCVCertificate().getCertificateBody().getValidTo();
                } else {
                    retDate = ((X509Certificate)cert).getNotAfter();
                }
                String subjectDN = CertTools.getSubjectDN(cert);
                String serNo = CertTools.getSerialNumberAsString(cert);
                getLogger().info("Certificate with subjectDN '" + subjectDN +
                    "' and serialNumber '" + serNo + "' expires at " + retDate + ".");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private Collection<Certificate> getExpiredCerts(Date findDate) {
        try {
        	getLogger().debug("Looking for cert with expireDate=" + findDate);
            Collection<Certificate> certs = ejb.getRemoteSession(CertificateStoreSessionRemote.class).findCertificatesByExpireTimeWithLimit(findDate);
            getLogger().debug("Found " + certs.size() + " certs.");
            return certs;
        } catch (Exception e) {
        	getLogger().error("Error getting list of certificates", e);
        }
        return null;
    }
}
