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

package org.ejbca.ui.cli.ca;

import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Re-publishes the certificates of all users belonging to a particular CA.
 * 
 * @version $Id$
 */
public class CARepublishCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CARepublishCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String ALL_KEY = "-all";
    private static final String CACERT_KEY = "-cacert";
    private static final String CACRL_KEY = "-cacrl";
    private static final String EECERT_KEY = "-eecert";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
        registerParameter(Parameter.createFlag(ALL_KEY,
                "Publish all certificates for each end entity instead of only the latest (default only publishes the latest)."));
        registerParameter(Parameter.createFlag(CACERT_KEY, "Publish CA certificate."));
        registerParameter(Parameter.createFlag(CACRL_KEY, "Publish CA CRL."));
        registerParameter(Parameter.createFlag(EECERT_KEY, "Publish End Entity certificates."));
    }

    @Override
    public String getMainCommand() {
        return "republish";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        boolean addAll = parameters.containsKey(ALL_KEY);
        boolean cacertmode = parameters.containsKey(CACERT_KEY);
        boolean cacrlmode = parameters.containsKey(CACRL_KEY);
        boolean eecertmode = parameters.containsKey(EECERT_KEY);
        String caname = parameters.get(CA_NAME_KEY);

        try {
            // Get the CAs info and id
            CAInfo cainfo;
            try {
                cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
            } catch (CADoesntExistsException e) {
                getLogger().info("CA with name '" + caname + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            if (cainfo == null) {
                getLogger().info("CA with name '" + caname + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // If no mode is give we will enable all modes (backwards compatibility for when there were no modes)
            if (!cacertmode && !cacrlmode && !eecertmode) {
                cacertmode = cacrlmode = eecertmode = true;
            }
            getLogger().info("Publishing with modes: cacert=" + cacertmode + ", cacrl=" + cacrlmode + ", eecert=" + eecertmode);
            // Publish the CAs certificate and CRL
            Collection<Certificate> cachain = cainfo.getCertificateChain();
            Iterator<Certificate> caiter = cachain.iterator();
            if (caiter.hasNext()) {
                final X509Certificate cacert = (X509Certificate) caiter.next();
                final byte[] crlbytes = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRL(cainfo.getSubjectDN(),
                        false);
                // Get the CRLnumber
                X509CRL crl;
                try {
                    crl = CertTools.getCRLfromByteArray(crlbytes);
                } catch (CRLException e) {
                    throw new IllegalStateException("Couldn't deserialize CRL", e);
                }
                int crlNumber = CrlExtensions.getCrlNumber(crl).intValue();
                final Collection<Integer> capublishers = cainfo.getCRLPublishers();
                // Store cert and CRL in ca publishers.
                if (capublishers != null) {
                    String fingerprint = CertTools.getFingerprintAsString(cacert);
                    if (cacertmode) {
                        getLogger().info("Publishing CA certificate to CA publishers.");
                        String username = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).findUsernameByCertSerno(
                                cacert.getSerialNumber(), cacert.getIssuerDN().getName());
                        CertificateInfo certinfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getCertificateInfo(
                                fingerprint);
                        EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).storeCertificate(getAuthenticationToken(),
                                capublishers, cacert, username, null, cainfo.getSubjectDN(), fingerprint, certinfo.getStatus(), certinfo.getType(),
                                certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo.getTag(),
                                certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), null);
                        getLogger().info("Certificate published for " + caname);
                    }
                    if (cacrlmode) {
                        if (crlbytes != null && crlbytes.length > 0 && crlNumber > 0) {
                            getLogger().info("Publishing CRL to CA publishers.");
                            EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).storeCRL(getAuthenticationToken(), capublishers,
                                    crlbytes, fingerprint, crlNumber, cainfo.getSubjectDN());
                            getLogger().info("CRL with number " + crlNumber + " published for " + caname);
                        } else {
                            getLogger().info("CRL not published, no CRL exists for CA.");
                        }
                    }
                } else {
                    getLogger().info("No publishers configured for the CA, no CA certificate or CRL published.");
                }
            } else {
                getLogger().info("CA does not have a certificate, no certificate or CRL published!");
            }

            if (eecertmode) {
                // Get all users for this CA
                Collection<EndEntityInformation> coll = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                        .findAllUsersByCaId(getAuthenticationToken(), cainfo.getCAId());
                Iterator<EndEntityInformation> iter = coll.iterator();
                while (iter.hasNext()) {
                    EndEntityInformation data = iter.next();
                    getLogger().info(
                            "User: " + data.getUsername() + ", \"" + data.getDN() + "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail()
                                    + ", " + data.getStatus() + ", " + data.getType().getHexValue() + ", " + data.getTokenType() + ", "
                                    + data.getHardTokenIssuerId() + ", " + data.getCertificateProfileId());

                    if (data.getCertificateProfileId() > 0) { // only if we find a
                        // certificate profile
                        CertificateProfile certProfile = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                .getCertificateProfile(data.getCertificateProfileId());
                        if (certProfile == null) {
                            getLogger().error("Can not get certificate profile with id: " + data.getCertificateProfileId());
                            continue;
                        }
                        // Get an ordered list of certificates, last expire date first
                        List<Certificate> certCol = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                                .findCertificatesByUsername(data.getUsername());
                        if ((certCol != null) && certCol.iterator().hasNext()) {
                            if (certProfile.getPublisherList() != null) {
                                getLogger().info(
                                        "Re-publishing user " + data.getUsername() + " to publishers in users certificate profile "
                                                + data.getCertificateProfileId());
                                if (addAll) {
                                    getLogger().info("Re-publishing all certificates (" + certCol.size() + ").");
                                    // Reverse the collection so we publish the latest certificate last
                                    Collections.reverse(certCol); // now the latest (last expire date) certificate is last in the List
                                    Iterator<Certificate> i = certCol.iterator();
                                    while (i.hasNext()) {
                                        X509Certificate c = (X509Certificate) i.next();
                                        publishCert(getAuthenticationToken(), data, certProfile, c);
                                    }
                                } else {
                                    // Only publish the latest one (last expire date)
                                    // The latest one is the first in the List according to findCertificatesByUsername()
                                    publishCert(getAuthenticationToken(), data, certProfile, (X509Certificate) certCol.iterator().next());
                                }
                            } else {
                                getLogger().info(
                                        "Not publishing certificate for user " + data.getUsername() + ", no publisher in certificate profile.");
                            }
                        } else {
                            getLogger().info("No certificate to publish for user " + data.getUsername());
                        }
                    } else {
                        getLogger().info("No certificate profile is set for user " + data.getUsername());
                    }
                }
               
            } // if (eecertmode)
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user was not authorized to CA " + caname);
            return CommandResult.AUTHORIZATION_FAILURE;
        }

    }

    private void publishCert(AuthenticationToken authenticationToken, EndEntityInformation data, CertificateProfile certProfile, X509Certificate cert) {
        try {
            String fingerprint = CertTools.getFingerprintAsString(cert);
            CertificateInfo certinfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getCertificateInfo(fingerprint);
            final String userDataDN = data.getCertificateDN();
            boolean ret = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).storeCertificate(authenticationToken,
                    certProfile.getPublisherList(), cert, data.getUsername(), data.getPassword(), userDataDN, fingerprint, certinfo.getStatus(),
                    certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo.getTag(),
                    certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), null);
            if (!ret) {
                getLogger().error(
                        "Failed to publish certificate for user " + data.getUsername() + ", continuing with next user. Publish returned false.");
            }
        } catch (Exception e) {
            // catch failure to publish one user and continue with the rest
            getLogger().error("Failed to publish certificate for user " + data.getUsername() + ", continuing with next user. " + e.getMessage());
        }
    }

    @Override
    public String getCommandDescription() {
        return "Re-publishes the certificates of a CA and/or all users issued by a particular CA. ";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "Default if none of cacert, cacrl or eecert is specific is to publish all types, you can specify one or several on the command line. "
                + "For example to only publish CA certificate and CRL, no end entity certificates: ca republish ManagementCA -cacert -cacrl"
                + "Example to only publish CA certificate and CRL, and latest end entity certificates: ca republish ManagementCA";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
