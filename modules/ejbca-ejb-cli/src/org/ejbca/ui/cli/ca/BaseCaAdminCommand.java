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

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.BaseCommand;

/**
 * Base for CA commands, contains common functions for CA operations
 * 
 * @version $Id$
 */
public abstract class BaseCaAdminCommand extends BaseCommand {

    protected static final String MAINCOMMAND = "ca";

    protected static final String defaultSuperAdminCN = "SuperAdmin";

    /** Private key alias in PKCS12 keystores */
    protected String privKeyAlias = "privateKey";
    protected char[] privateKeyPass = null;

    /**
     * Retrieves the complete certificate chain from the CA
     * 
     * @param human readable name of CA
     * @return array of certificates, from ISignSession.getCertificateChain()
     */
    protected Collection<Certificate> getCertChain(AuthenticationToken authenticationToken, String caname) throws Exception {
        getLogger().trace(">getCertChain()");
        Collection<Certificate> returnval = new ArrayList<Certificate>();
        try {
            CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
            if (cainfo != null) {
                returnval = cainfo.getCertificateChain();
            }
        } catch (Exception e) {
            getLogger().error("Error while getting certfificate chain from CA.", e);
        }
        getLogger().trace("<getCertChain()");
        return returnval;
    }

    protected void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile) throws NoSuchAlgorithmException, IOException, NoSuchProviderException,
            InvalidKeyException, SignatureException, OperatorCreationException, PKCSException {
        getLogger().trace(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name(dn), rsaKeys.getPublic(), new DERSet(),
                rsaKeys.getPrivate(), null);

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
        getLogger().info("Verify returned " + verify);

        if (verify == false) {
            getLogger().info("Aborting!");
            return;
        }

        FileOutputStream os1 = new FileOutputStream(reqfile);
        os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        os1.write(Base64.encode(bOut.toByteArray()));
        os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        os1.close();
        getLogger().info("CertificationRequest '" + reqfile + "' generated successfully.");
        getLogger().trace("<makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");
    }

    protected void createCRL(final String cliUsername, final String cliPassword, final String issuerdn, final boolean deltaCRL) {
        getLogger().trace(">createCRL()");
        try {
            if (issuerdn != null) {
                CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), issuerdn.hashCode());
                if (!deltaCRL) {
                    ejb.getRemoteSession(PublishingCrlSessionRemote.class).forceCRL(getAdmin(cliUserName, cliPassword), cainfo.getCAId());
                    int number = ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuerdn, false);
                    getLogger().info("CRL with number " + number + " generated.");
                } else {
                    ejb.getRemoteSession(PublishingCrlSessionRemote.class).forceDeltaCRL(getAdmin(cliUserName, cliPassword), cainfo.getCAId());
                    int number = ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuerdn, true);
                    getLogger().info("Delta CRL with number " + number + " generated.");
                }
            } else {
                int createdcrls = ejb.getRemoteSession(PublishingCrlSessionRemote.class).createCRLs(getAdmin(cliUserName, cliPassword));
                getLogger().info("  " + createdcrls + " CRLs have been created.");
                int createddeltacrls = ejb.getRemoteSession(PublishingCrlSessionRemote.class).createDeltaCRLs(getAdmin(cliUserName, cliPassword));
                getLogger().info("  " + createddeltacrls + " delta CRLs have been created.");
            }
        } catch (Exception e) {
            getLogger().error("Error while getting certficate chain from CA.", e);
        }
        getLogger().trace(">createCRL()");
    }

    protected String getIssuerDN(AuthenticationToken authenticationToken, String caname) throws Exception {
        CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
        return cainfo != null ? cainfo.getSubjectDN() : null;
    }

    protected CAInfo getCAInfo(AuthenticationToken authenticationToken, String caname) throws Exception {
        CAInfo result;
        try {
            result = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caname);
        } catch (Exception e) {
            getLogger().debug("Error retriving CA " + caname + " info.", e);
            throw new Exception("Error retriving CA " + caname + " info.", e);
        }
        if (result == null) {
            getLogger().debug("CA " + caname + " not found.");
            throw new Exception("CA " + caname + " not found.");
        }
        return result;
    }

    protected void initAuthorizationModule(AuthenticationToken authenticationToken, int caid, String superAdminCN) throws AccessRuleNotFoundException, RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
    	if (superAdminCN == null) {
    		getLogger().info("Not initializing authorization module.");
    	} else {
    		getLogger().info("Initalizing authorization module with caid="+caid+" and superadmin CN '"+superAdminCN+"'.");
    	}
    	ejb.getRemoteSession(ComplexAccessControlSessionRemote.class).initializeAuthorizationModule(authenticationToken, caid, superAdminCN);
    } // initAuthorizationModule
    
    protected String getAvailableCasString(String cliUserName, String cliPassword) {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCAs(getAdmin(cliUserName, cliPassword))) {
				final String caName = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), nextId.intValue()).getName();
				if (existingCas.length()>0) {
					existingCas.append(", ");
				}
				existingCas.append("\"").append(caName).append("\"");
			}
		} catch (Exception e) {
			existingCas.append("<unable to fetch available CA(s)>");
		}
		return existingCas.toString();
    }

    protected String getAvailableEepsString(String cliUserName, String cliPassword) {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(getAdmin(cliUserName, cliPassword))) {
				final String caName = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(nextId.intValue());
				if (existingCas.length()>0) {
					existingCas.append(", ");
				}
				existingCas.append("\"").append(caName).append("\"");
			}
		} catch (Exception e) {
			existingCas.append("<unable to fetch available End Entity Profile(s)>");
		}
		return existingCas.toString();
    }

    protected String getAvailableEndUserCpsString(String cliUserName, String cliPassword) {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : ejb.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(CertificateConstants.CERTTYPE_ENDENTITY, EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCAs(getAdmin(cliUserName, cliPassword)))) {
				final String caName = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(nextId.intValue());
				if (existingCas.length()>0) {
					existingCas.append(", ");
				}
				existingCas.append("\"").append(caName).append("\"");
			}
		} catch (Exception e) {
			existingCas.append("<unable to fetch available Certificate Profile(s)>");
		}
		return existingCas.toString();
    }
}
