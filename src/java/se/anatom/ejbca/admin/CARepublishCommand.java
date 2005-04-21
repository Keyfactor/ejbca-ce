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
import java.util.Iterator;

import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.store.CertificateDataBean;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.util.CertTools;


/**
 * Re-publishes the certificates of all users beloinging to a particular CA.
 *
 * @version $Id: CARepublishCommand.java,v 1.3 2005-04-21 15:14:19 herrvendil Exp $
 */
public class CARepublishCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of RaListUsersCommand
     *
     * @param args command line arguments
     */
    public CARepublishCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                getOutputStream().println("Usage: CA republish <CA name>");
                return;
            }

            String caname = args[1];
                        
            // Get the CAs info and id
            CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caname);
            // Publish the CAns certificate and CRL
            Collection cachain = cainfo.getCertificateChain();
            Iterator caiter = cachain.iterator();
            if (caiter.hasNext()) {
                X509Certificate cacert = (X509Certificate)caiter.next();
                int crlNumber = getCertificateStoreSession().getLastCRLNumber(administrator, cainfo.getSubjectDN());
                byte[] crlbytes = getCertificateStoreSession().getLastCRL(administrator, cainfo.getSubjectDN());
                Collection capublishers = cainfo.getCRLPublishers();
                // Store cert and CRL in ca publishers.
                if(capublishers != null) {
                    int certtype = CertificateDataBean.CERTTYPE_SUBCA;	
                    if (cainfo.getSignedBy() == CAInfo.SELFSIGNED)
                        certtype = CertificateDataBean.CERTTYPE_ROOTCA;  
                    String fingerprint = CertTools.getFingerprintAsString(cacert);
                    getPublisherSession().storeCertificate(administrator, capublishers, cacert, fingerprint, null , fingerprint, CertificateDataBean.CERT_ACTIVE, certtype, null);
                    getOutputStream().println("Certificate published for "+caname);
                    if ( (crlbytes != null) && (crlbytes.length > 0) && (crlNumber > 0) ) {
                        getPublisherSession().storeCRL(administrator, capublishers, crlbytes, fingerprint, crlNumber);                        
                        getOutputStream().println("CRL published for "+caname);
                    } else {
                        getOutputStream().println("CRL not published, no CRL createed for CA?");
                    }
                } else {
                    getOutputStream().println("No publishers configured for the CA, no CA certificate or CRL published.");
                }
            } else {
                getOutputStream().println("CA does not have a certificate, no certificate or CRL published!");
            }
            
            // Get all users for this CA
            Collection coll = getAdminSession().findAllUsersByCaId(administrator, cainfo.getCAId());
            Iterator iter = coll.iterator();
            while (iter.hasNext()) {
                UserDataVO data = (UserDataVO) iter.next();
                getOutputStream().println("User: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType() + ", " + data.getTokenType() + ", " + data.getHardTokenIssuerId()+", "+data.getCertificateProfileId());

                if (data.getCertificateProfileId() > 0) { // only if we find a certificate profile
                    CertificateProfile certProfile = getCertificateStoreSession().getCertificateProfile(administrator, data.getCertificateProfileId());
                    if (certProfile == null) {
                        error("Can not get certificate profile with id: "+data.getCertificateProfileId());
                        continue;
                    }
                    Collection certCol = getCertificateStoreSession().findCertificatesByUsername(administrator, data.getUsername());
                    Iterator certIter = certCol.iterator();
                    X509Certificate cert = null;
                    if (certIter.hasNext()) {
                        cert = (X509Certificate)certIter.next();
                    }
                    X509Certificate tmpCert = null;
                    while (certIter.hasNext())
                    {
                        // Make sure we get the latest certificate of them all (if there are more than one for this user).
                        tmpCert = (X509Certificate)certIter.next();
                        if (tmpCert.getNotBefore().compareTo(cert.getNotBefore()) > 0) {
                            cert = tmpCert;
                        }
                    }
                    if (cert != null) {
                        if(certProfile.getPublisherList() != null) {
                            getOutputStream().println("Re-publishing user "+data.getUsername());
                            try {
                                String fingerprint = CertTools.getFingerprintAsString(cert);
                                getPublisherSession().storeCertificate(administrator, certProfile.getPublisherList(), cert, data.getUsername(), data.getPassword(), fingerprint, CertificateDataBean.CERT_ACTIVE, certProfile.getType(), null);                                
                            } catch (Exception e) {
                                // catch failure to publish one user and continue with the rest
                                error("Failed to publish certificate for user "+data.getUsername()+", continuing with next user.");
                            }
                        } else {
                            getOutputStream().println("Not publishing user "+data.getUsername()+", no publisher in certificate profile.");
                        }
                    } else {
                        getOutputStream().println("No certificate to publish for user "+data.getUsername());
                    }
                } else {
                    getOutputStream().println("No certificate profile id exists for user "+data.getUsername());
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
