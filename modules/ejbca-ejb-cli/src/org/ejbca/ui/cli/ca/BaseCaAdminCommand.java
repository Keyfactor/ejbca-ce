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
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.util.CertTools;
import org.cesecore.util.Base64;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
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
    protected Collection<Certificate> getCertChain(String caname) throws Exception {
        getLogger().trace(">getCertChain()");
        Collection<Certificate> returnval = new ArrayList<Certificate>();
        try {
            CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), caname);
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
            InvalidKeyException, SignatureException {
        getLogger().trace(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name(dn), rsaKeys.getPublic(), new DERSet(),
                rsaKeys.getPrivate());

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
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
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

    protected void createCRL(String issuerdn, boolean deltaCRL) {
        getLogger().trace(">createCRL()");
        try {
            if (issuerdn != null) {
                CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), issuerdn.hashCode());
                if (!deltaCRL) {
                    ejb.getCrlCreateSession().forceCRL(getAdmin(), cainfo.getCAId());
                    int number = ejb.getCrlStoreSession().getLastCRLNumber(issuerdn, false);
                    getLogger().info("CRL with number " + number + " generated.");
                } else {
                    ejb.getCrlCreateSession().forceDeltaCRL(getAdmin(), cainfo.getCAId());
                    int number = ejb.getCrlStoreSession().getLastCRLNumber(issuerdn, true);
                    getLogger().info("Delta CRL with number " + number + " generated.");
                }
            } else {
                int createdcrls = ejb.getCrlCreateSession().createCRLs(getAdmin());
                getLogger().info("  " + createdcrls + " CRLs have been created.");
                int createddeltacrls = ejb.getCrlCreateSession().createDeltaCRLs(getAdmin());
                getLogger().info("  " + createddeltacrls + " delta CRLs have been created.");
            }
        } catch (Exception e) {
            getLogger().error("Error while getting certficate chain from CA.", e);
        }
        getLogger().trace(">createCRL()");
    }

    protected String getIssuerDN(String caname) throws Exception {
        CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), caname);
        return cainfo != null ? cainfo.getSubjectDN() : null;
    }

    protected CAInfo getCAInfo(String caname) throws Exception {
        CAInfo result;
        try {
            result = ejb.getCaSession().getCAInfo(getAdmin(), caname);
        } catch (Exception e) {
            getLogger().debug("Error retriving CA " + caname + " info.", e);
            throw new Exception("Error retriving CA " + caname + " info.");
        }
        if (result == null) {
            getLogger().debug("CA " + caname + " not found.");
            throw new Exception("CA " + caname + " not found.");
        }
        return result;
    }

    protected void initAuthorizationModule(int caid, String superAdminCN) throws AdminGroupExistsException {
        getLogger().info("Initalizing Temporary Authorization Module with caid="+caid+" and superadmin CN '"+superAdminCN+"'.");
        ejb.getAdminGroupSession().init(getAdmin(), caid, superAdminCN);     
    } // initAuthorizationModule
    
    protected String getAvailableCasString() {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : ejb.getCaSession().getAvailableCAs(getAdmin())) {
				final String caName = ejb.getCaSession().getCAInfo(getAdmin(), nextId.intValue()).getName();
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

    protected String getAvailableEepsString() {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : ejb.getEndEntityProfileSession().getAuthorizedEndEntityProfileIds(getAdmin())) {
				final String caName = ejb.getEndEntityProfileSession().getEndEntityProfileName(getAdmin(), nextId.intValue());
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

    protected String getAvailableEndUserCpsString() {
		// List available CAs by name
		final StringBuilder existingCas = new StringBuilder();
		try {
			for (final Integer nextId : ejb.getCertificateProfileSession().getAuthorizedCertificateProfileIds(SecConst.CERTTYPE_ENDENTITY, ejb.getCaSession().getAvailableCAs(getAdmin()))) {
				final String caName = ejb.getCertificateProfileSession().getCertificateProfileName(nextId.intValue());
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
