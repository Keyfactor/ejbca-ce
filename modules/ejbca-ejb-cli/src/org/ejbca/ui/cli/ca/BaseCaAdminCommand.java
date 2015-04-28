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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Base for CA commands, contains common functions for CA operations
 * 
 * @version $Id$
 */
public abstract class BaseCaAdminCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(BaseCaAdminCommand.class);

    protected static final String MAINCOMMAND = "ca";

    protected static final String defaultSuperAdminCN = "SuperAdmin";

    /** Private key alias in PKCS12 keystores */
    protected String privKeyAlias = "privateKey";
    protected char[] privateKeyPass = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { MAINCOMMAND };
    }

    /**
     * Retrieves the complete certificate chain from the CA
     * 
     * @param human readable name of CA
     * @return a Collection of certificates
     */
    protected Collection<Certificate> getCertChain(AuthenticationToken authenticationToken, String caname) {
        log.trace(">getCertChain()");
        Collection<Certificate> returnval = new ArrayList<Certificate>();
        try {
            CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
            if (cainfo != null) {
                returnval = cainfo.getCertificateChain();
            }
        } catch (Exception e) {
            log.error("Error while getting certfificate chain from CA.", e);
        }
        log.trace("<getCertChain()");
        return returnval;
    }

    protected void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile) throws NoSuchAlgorithmException, IOException, NoSuchProviderException,
            InvalidKeyException, SignatureException, OperatorCreationException, PKCSException {
        log.trace(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name(dn),
                rsaKeys.getPublic(), new DERSet(), rsaKeys.getPrivate(), null);

        /*
         * We don't use these unnecessary attributes DERConstructedSequence kName
         * = new DERConstructedSequence(); DERConstructedSet kSeq = new
         * DERConstructedSet();
         * kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
         * kSeq.addObject(new DERIA5String("foo@bar.se"));
         * kName.addObject(kSeq); req.setAttributes(kName);
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        ContentVerifierProvider contentVerifier = CertTools.genContentVerifierProvider(rsaKeys.getPublic());
        boolean verify = req2.isSignatureValid(contentVerifier); //req2.verify();
        log.info("Verify returned " + verify);

        if (verify == false) {
            log.info("Aborting!");
            return;
        }

        FileOutputStream os1 = new FileOutputStream(reqfile);
        os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        os1.write(Base64.encode(bOut.toByteArray()));
        os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        os1.close();
        log.info("CertificationRequest '" + reqfile + "' generated successfully.");
        log.trace("<makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");
    }

    protected void createCRL(final String issuerdn, final boolean deltaCRL) {
        log.trace(">createCRL()");
        try {
            if (issuerdn != null) {
                CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                        issuerdn.hashCode());
                if (!deltaCRL) {
                    EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class).forceCRL(getAuthenticationToken(), cainfo.getCAId());
                    int number = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuerdn, false);
                    log.info("CRL with number " + number + " generated.");
                } else {
                    EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class).forceDeltaCRL(getAuthenticationToken(),
                            cainfo.getCAId());
                    int number = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuerdn, true);
                    log.info("Delta CRL with number " + number + " generated.");
                }
            } else {
                int createdcrls = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class).createCRLs(getAuthenticationToken());
                log.info("  " + createdcrls + " CRLs have been created.");
                int createddeltacrls = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class).createDeltaCRLs(
                        getAuthenticationToken());
                log.info("  " + createddeltacrls + " delta CRLs have been created.");
            }
        } catch (Exception e) {
            log.error("Error while creating CRL for CA: " + issuerdn, e);
        }
        log.trace(">createCRL()");
    }

    protected String getIssuerDN(AuthenticationToken authenticationToken, String caname) throws CADoesntExistsException, AuthorizationDeniedException {
        CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
        return cainfo != null ? cainfo.getSubjectDN() : null;
    }

    protected CAInfo getCAInfo(AuthenticationToken authenticationToken, String caname) {
        CAInfo result = null;
        try {
            result = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
        } catch (CADoesntExistsException e) {
            log.debug("Error retriving CA " + caname + " info.", e);
        } catch (AuthorizationDeniedException e) {
            log.error("Authorization denied", e);
        }
        if (result == null) {
            log.debug("CA " + caname + " not found.");
        }
        return result;
    }

    protected void initAuthorizationModule(AuthenticationToken authenticationToken, int caid, String superAdminCN)
            throws AccessRuleNotFoundException, RoleExistsException, AuthorizationDeniedException {
        if (superAdminCN == null) {
            log.info("Not initializing authorization module.");
        } else {
            log.info("Initalizing authorization module with caid=" + caid + " and superadmin CN '" + superAdminCN + "'.");
        }
        EjbRemoteHelper.INSTANCE.getRemoteSession(ComplexAccessControlSessionRemote.class).initializeAuthorizationModule(authenticationToken, caid,
                superAdminCN);
    } // initAuthorizationModule

    protected String getAvailableCasString() {
        // List available CAs by name
        final StringBuilder existingCas = new StringBuilder();
        try {
            for (final Integer nextId : EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaIds(getAuthenticationToken())) {
                final String caName = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class)
                        .getCAInfo(getAuthenticationToken(), nextId.intValue()).getName();
                if (existingCas.length() > 0) {
                    existingCas.append(", ");
                }
                existingCas.append("\"").append(caName).append("\"");
            }
        } catch (Exception e) {
            existingCas.append("<unable to fetch available CA(s)>");
        }
        return existingCas.toString();
    }

    protected String getAvailableEepsString(final String endentityAccessRule) {
        // List available EndEntityProfiles by name
        final StringBuilder availableEEPs = new StringBuilder();
        try {
            for (final Integer nextId : EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                    .getAuthorizedEndEntityProfileIds(getAuthenticationToken(), endentityAccessRule)) {
                final String eepName = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(
                        nextId.intValue());
                if (availableEEPs.length() > 0) {
                    availableEEPs.append(", ");
                }
                availableEEPs.append("\"").append(eepName).append("\"");
            }
        } catch (Exception e) {
            availableEEPs.append("<unable to fetch available End Entity Profile(s)>");
        }
        return availableEEPs.toString();
    }

    protected String getAvailableEndUserCpsString() {
        // List available CertificateProfiles by name
        final StringBuilder availableCPs = new StringBuilder();
        try {
            for (final Integer nextId : EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                    .getAuthorizedCertificateProfileIds(getAuthenticationToken(), CertificateConstants.CERTTYPE_ENDENTITY)) {
                final String cpName = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(
                        nextId.intValue());
                if (availableCPs.length() > 0) {
                    availableCPs.append(", ");
                }
                availableCPs.append("\"").append(cpName).append("\"");
            }
        } catch (Exception e) {
            availableCPs.append("<unable to fetch available Certificate Profile(s)>");
        }
        return availableCPs.toString();
    }
    
    protected String getCaList() {
        final String TAB = "    ";
        Collection<Integer> cas = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaIds(getAuthenticationToken());
        String casList = "Available CAs:\n";
        for (Integer caid : cas) {
            CAInfo info;
            try {
                info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caid);
                casList += TAB + info.getName() + ":" + info.getCAToken().getSignatureAlgorithm() + "\n";
            } catch (CADoesntExistsException e) {
                //This can't happen
            } catch (AuthorizationDeniedException e) {
                casList = "Current CLI user does not have authorization to any CAs.\n";
                break;
            }
        }
        return casList;
    }
}
