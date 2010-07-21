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

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.ejb.EJB;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.CreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CliTools;
import org.ejbca.util.CryptoProviderTools;

/**
 * Re-publishes the certificates of all users belonging to a particular CA.
 * 
 * @version $Id$
 */
public class CARepublishCommand extends BaseCaAdminCommand {

    @EJB
    private CAAdminSessionRemote caAdminSession;
    
    @EJB
    private CertificateStoreSessionRemote certificateStoreSession;

    @EJB 
    private PublisherSessionRemote publisherSession;
    
    @EJB
    private CreateCRLSessionRemote createCrlSession;
    
    @EJB
    private UserAdminSessionRemote userAdminSession;
    
    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "republish";
    }

    public String getDescription() {
        return "Re-publishes the certificates of all users belonging to a particular CA";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            // Get and remove switches
            List<String> argsList = CliTools.getAsModifyableList(args);
            boolean addAll = argsList.remove("-all");
            args = argsList.toArray(new String[0]);
            // Parse the rest of the arguments
            if (args.length < 2) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <CA name> [-all]");
                getLogger().info(" -all   republish all certificates for each user instead of just the latest");
                return;
            }
            String caname = args[1];
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo = caAdminSession.getCAInfo(getAdmin(), caname);
            if (cainfo == null) {
                getLogger().info("CA with name '" + caname + "' does not exist.");
                return;
            }
            // Publish the CAs certificate and CRL
            Collection cachain = cainfo.getCertificateChain();
            Iterator caiter = cachain.iterator();
            if (caiter.hasNext()) {
                X509Certificate cacert = (X509Certificate) caiter.next();
                byte[] crlbytes = createCrlSession.getLastCRL(getAdmin(), cainfo.getSubjectDN(), false);
                Collection capublishers = cainfo.getCRLPublishers();
                // Store cert and CRL in ca publishers.
                if (capublishers != null) {
                    String fingerprint = CertTools.getFingerprintAsString(cacert);
                    String username = certificateStoreSession.findUsernameByCertSerno(getAdmin(), cacert.getSerialNumber(), cacert.getIssuerDN().getName());
                    CertificateInfo certinfo = certificateStoreSession.getCertificateInfo(getAdmin(), fingerprint);
                    publisherSession.storeCertificate(getAdmin(), capublishers, cacert, username, null, cainfo.getSubjectDN(), fingerprint, certinfo
                            .getStatus(), certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo.getTag(),
                            certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), null);
                    getLogger().info("Certificate published for " + caname);
                    if ((crlbytes != null) && (crlbytes.length > 0)) {
                        publisherSession.storeCRL(getAdmin(), capublishers, crlbytes, fingerprint, cainfo.getSubjectDN());
                        getLogger().info("CRL published for " + caname);
                    } else {
                        getLogger().info("CRL not published, no CRL createed for CA?");
                    }
                } else {
                    getLogger().info("No publishers configured for the CA, no CA certificate or CRL published.");
                }
            } else {
                getLogger().info("CA does not have a certificate, no certificate or CRL published!");
            }

            // Get all users for this CA
            Collection coll = userAdminSession.findAllUsersByCaId(getAdmin(), cainfo.getCAId());
            Iterator iter = coll.iterator();
            while (iter.hasNext()) {
                UserDataVO data = (UserDataVO) iter.next();
                getLogger().info(
                        "User: " + data.getUsername() + ", \"" + data.getDN() + "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", "
                                + data.getStatus() + ", " + data.getType() + ", " + data.getTokenType() + ", " + data.getHardTokenIssuerId() + ", "
                                + data.getCertificateProfileId());

                if (data.getCertificateProfileId() > 0) { // only if we find a
                    // certificate profile
                    CertificateProfile certProfile = certificateStoreSession.getCertificateProfile(getAdmin(), data.getCertificateProfileId());
                    if (certProfile == null) {
                        getLogger().error("Can not get certificate profile with id: " + data.getCertificateProfileId());
                        continue;
                    }
                    Collection certCol = certificateStoreSession.findCertificatesByUsername(getAdmin(), data.getUsername());
                    Iterator certIter = certCol.iterator();
                    X509Certificate cert = null;
                    if (certIter.hasNext()) {
                        cert = (X509Certificate) certIter.next();
                    }
                    X509Certificate tmpCert = null;
                    while (certIter.hasNext()) {
                        // Make sure we get the latest certificate of them all
                        // (if there are more than one for this user).
                        tmpCert = (X509Certificate) certIter.next();
                        if (tmpCert.getNotBefore().compareTo(cert.getNotBefore()) > 0) {
                            cert = tmpCert;
                        }
                    }
                    if (cert != null) {
                        if (certProfile.getPublisherList() != null) {
                            getLogger().info("Re-publishing user " + data.getUsername());
                            if (addAll) {
                                getLogger().info("Re-publishing all certificates (" + certCol.size() + ").");
                                Iterator i = certCol.iterator();
                                while (i.hasNext()) {
                                    X509Certificate c = (X509Certificate) i.next();
                                    publishCert(data, certProfile, c);
                                }
                            }
                            // Publish the latest again, last to make sure that
                            // is the one stuck in LDAP for example
                            publishCert(data, certProfile, cert);
                        } else {
                            getLogger().info("Not publishing user " + data.getUsername() + ", no publisher in certificate profile.");
                        }
                    } else {
                        getLogger().info("No certificate to publish for user " + data.getUsername());
                    }
                } else {
                    getLogger().info("No certificate profile id exists for user " + data.getUsername());
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private void publishCert(UserDataVO data, CertificateProfile certProfile, X509Certificate cert) {
        try {
            String fingerprint = CertTools.getFingerprintAsString(cert);
            CertificateInfo certinfo = certificateStoreSession.getCertificateInfo(getAdmin(), fingerprint);
            final String userDataDN = data.getDN();
            publisherSession.storeCertificate(getAdmin(), certProfile.getPublisherList(), cert, data.getUsername(), data.getPassword(), userDataDN,
                    fingerprint, certinfo.getStatus(), certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo
                            .getTag(), certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), null);
        } catch (Exception e) {
            // catch failure to publish one user and continue with the rest
            getLogger().error("Failed to publish certificate for user " + data.getUsername() + ", continuing with next user.");
        }
    }
}
