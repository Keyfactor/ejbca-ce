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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;

import javax.naming.Context;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.crl.ICreateCRLSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;


/**
 * Base for CA commands, contains comom functions for CA operations
 *
 * @version $Id: BaseCaAdminCommand.java,v 1.21 2005-04-29 08:15:45 anatom Exp $
 */
public abstract class BaseCaAdminCommand extends BaseAdminCommand {
    /** Private key alias in PKCS12 keystores */
    protected String privKeyAlias = "privateKey";
    protected char[] privateKeyPass = null;
    
    /**
     * Creates a new instance of BaseCaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseCaAdminCommand(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER);
        // Install BouncyCastle provider
        CertTools.installBCProvider();
    }
    
    /** Retrieves the complete certificate chain from the CA
     *
     * @param human readable name of CA 
     * @return array of certificates, from ISignSession.getCertificateChain()
     */   
    protected Collection getCertChain(String caname) throws Exception{
        debug(">getCertChain()");
        Collection returnval = new ArrayList();
        try {
            CAInfo cainfo = this.getCAAdminSessionRemote().getCAInfo(administrator,caname);
            if (cainfo != null) {
                returnval = cainfo.getCertificateChain();
            } 
        } catch (Exception e) {
            error("Error while getting certfificate chain from CA.", e);
        }
        debug("<getCertChain()");
        return returnval;
    } // getCertChain 

    protected void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile)
        throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, 
            SignatureException {
        debug(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name(dn), rsaKeys.getPublic(), null, rsaKeys.getPrivate());

        /* We don't use these uneccesary attributes
        DERConstructedSequence kName = new DERConstructedSequence();
        DERConstructedSet  kSeq = new DERConstructedSet();
        kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
        kSeq.addObject(new DERIA5String("foo@bar.se"));
        kName.addObject(kSeq);
        req.setAttributes(kName);
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        System.out.println("Verify returned " + verify);

        if (verify == false) {
            System.out.println("Aborting!");

            return;
        }

        FileOutputStream os1 = new FileOutputStream(reqfile);
        os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        os1.write(Base64.encode(bOut.toByteArray()));
        os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        os1.close();
        System.out.println("CertificationRequest '" + reqfile + "' generated successfully.");
        debug("<makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");
    } // makeCertRequest

    protected void createCRL(String issuerdn) {
        debug(">createCRL()");

        try {
            Context context = getInitialContext();
            ICreateCRLSessionHome home = (ICreateCRLSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
                        "CreateCRLSession"), ICreateCRLSessionHome.class);
            if(issuerdn != null){
              home.create().run(administrator, issuerdn);

              ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
                        "CertificateStoreSession"), ICertificateStoreSessionHome.class);
              ICertificateStoreSessionRemote storeremote = storehome.create();
              int number = storeremote.getLastCRLNumber(administrator, issuerdn);
              System.out.println("CRL with number " + number + " generated.");
            }else{
            	int createdcrls = home.create().createCRLs(administrator);
            	System.out.println("  " + createdcrls + " CRLs have been created.");	
            }
        } catch (Exception e) {
            error("Error while getting certficate chain from CA.", e);
        }

        debug(">createCRL()");
   } // createCRL
    
   protected String getIssuerDN(String caname) throws Exception{            
      CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caname);
      return cainfo.getSubjectDN();  
   }
   
}
