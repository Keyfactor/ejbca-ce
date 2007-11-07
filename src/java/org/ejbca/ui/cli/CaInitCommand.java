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
 
package org.ejbca.ui.cli;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.naming.Context;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;
import org.ejbca.util.StringTools;


/**
 * Inits the CA by creating the first CRL and publiching the CRL and CA certificate.
 *
 * @version $Id: CaInitCommand.java,v 1.21 2007-11-07 13:25:57 anatom Exp $
 */
public class CaInitCommand extends BaseCaAdminCommand {

    /**
     * Creates a new instance of CaInitCommand
     *
     * @param args command line arguments
     */
    public CaInitCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        // Create new CA.
        if (args.length < 7) {
           String msg = "Used to create a Root CA using RSA keys.";
           msg += "\nUsage: CA init <caname> <dn> <catokentype> <catokenpassword> <keyspec> <keytype> <validity-days> <policyID> <signalgorithm> [<catokenproperties>]";
           msg += "\ncatokentype defines if the CA should be created with soft keys or on a HSM. Use soft for software keys and org.ejbca.core.model.ca.catoken.NFastCAToken for nCipher.";
           msg += "\ncatokenpassword is the password for the CA token. Set to 'null' to use the default system password for Soft token CAs";
           msg += "\nkeytype is RSA or ECDSA.";
           msg += "\nkeyspec for RSA keys is size of RSA keys (1024, 2048, 4096).";
           msg += "\nkeyspec for ECDSA keys is name of curve or 'implicitlyCA', see docs.";
           msg += "\npolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' or objectID and crlurl as \"2.5.29.32.0 http://foo.bar.com/mycps.txt\".";
           msg += "\nsignalgorithm is SHA1WithRSA or SHA1WithECDSA.";
           msg += "\ncatokenproperties is a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in Admin gui";
           throw new IllegalAdminCommandException(msg);
        }
            
        try {             	
            String caname = args[1];
            String dn = CertTools.stringToBCDNString(args[2]);
            dn = StringTools.strip(dn);
            String catokentype = args[3];
            String catokenpassword = args[4];
            String keyspec = args[5];
            String keytype = args[6];
            int validity = Integer.parseInt(args[7]);
            String policyId = args[8];
            String signAlg = args[9];
            String catokenproperties = null;
            if (args.length > 10 && !"soft".equals(catokentype)) {
            	if (!(new File(args[10] )).exists()) {
            		throw new IllegalAdminCommandException("File " + args[10] + " does not exist");
            	}
                catokenproperties = new String(FileTools.readFiletoBuffer(args[10]));
            }
            ArrayList policies = new ArrayList(1);
            if ( (policyId != null) && (policyId.toLowerCase().trim().equals("null")) ) {
            	policyId = null;
            } else {
            	String[] array = policyId.split(" ");
            	String id = array[0];
            	String cpsurl;
            	if(array.length > 1) {
            		cpsurl = array[1];
            	} else {
            		cpsurl = "";
            	}
            	policies.add(new CertificatePolicy(id, null, cpsurl));
            }
                        
            getOutputStream().println("Initializing CA");            
            
            getOutputStream().println("Generating rootCA keystore:");
            getOutputStream().println("CA name: "+caname);
            getOutputStream().println("DN: "+dn);
            getOutputStream().println("CA token type: "+catokentype);
            getOutputStream().println("CA token password: "+catokenpassword);
            getOutputStream().println("Keyspec: "+keyspec);
            getOutputStream().println("Keytype: "+keytype);
            getOutputStream().println("Validity (days): "+validity);
            getOutputStream().println("Policy ID: "+policyId);
            getOutputStream().println("Signature alg: "+signAlg);
            getOutputStream().println("CA token properties: "+catokenproperties);
                            
            initAuthorizationModule(dn.hashCode());
            // Define CAToken type (soft token or hsm).
            CATokenInfo catokeninfo = null;
            if ( catokentype.equals("soft")) {
	            SoftCATokenInfo softcatokeninfo = new SoftCATokenInfo();
	            if (!catokenpassword.equalsIgnoreCase("null")) {
		        	softcatokeninfo.setAuthenticationCode(catokenpassword);	            	
	            }
	            softcatokeninfo.setSignKeySpec(keyspec);
	            softcatokeninfo.setSignKeyAlgorithm(keytype);
	            softcatokeninfo.setSignatureAlgorithm(signAlg);
	            softcatokeninfo.setEncKeySpec("2048");
	            softcatokeninfo.setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
	            softcatokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
	            catokeninfo = softcatokeninfo;
            } else {
            	HardCATokenInfo hardcatokeninfo = new HardCATokenInfo();
            	hardcatokeninfo.setAuthenticationCode(catokenpassword);
            	hardcatokeninfo.setCATokenStatus(ICAToken.STATUS_ACTIVE);
            	hardcatokeninfo.setClassPath(catokentype);
            	hardcatokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
            	hardcatokeninfo.setProperties(catokenproperties);
            	hardcatokeninfo.setSignatureAlgorithm(signAlg);
            	catokeninfo = hardcatokeninfo;
            }
            
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            String keySpec = keyspec;
            if (keytype.equals(CATokenConstants.KEYALGORITHM_RSA)) {
            	// Never use larger keys than 2048 bit RSA for OCSP signing
            	int len = Integer.parseInt(keySpec);
            	if (len > 2048) {
            		keySpec = "2048";				 
            	}
            }
            extendedcaservices.add(
              new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                                    "CN=OCSPSignerCertificate, " + dn,
                                    "",
                                    keySpec,
                                    keytype));
            extendedcaservices.add(
                    new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                                          "CN=XKMSCertificate, " + dn,
                                          "",
                                          keySpec,
                                          keytype));
              
            
            X509CAInfo cainfo = new X509CAInfo(dn, 
                                             caname, SecConst.CA_ACTIVE, new Date(),
                                             "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                                             validity, 
                                             null, // Expiretime                                             
                                             CAInfo.CATYPE_X509,
                                             CAInfo.SELFSIGNED,
                                             (Collection) null,
                                             catokeninfo,
                                             "Initial CA",
                                             -1, null,
                                             policies, // PolicyId
                                             24, // CRLPeriod
                                             0, // CRLIssueInterval
                                             10, // CRLOverlapTime
                                             new ArrayList(),
                                             true, // Authority Key Identifier
                                             false, // Authority Key Identifier Critical
                                             true, // CRL Number
                                             false, // CRL Number Critical
                                             "", // Default CRL Dist Point
                                             "", // Default CRL Issuer
                                             "", // Default OCSP Service Locator
                                             "", // CA defined freshest CRL
                                             true, // Finish User
                                             extendedcaservices,
			                                 false, // use default utf8 settings
			                                 new ArrayList(), // Approvals Settings
			                                 1, // Number of Req approvals
			                                 false, // Use UTF8 subject DN by default
			                                 true // Use LDAP DN order by default
			                                 );
            
            getOutputStream().println("Creating CA...");
            ICAAdminSessionRemote remote = getCAAdminSessionRemote();
            remote.createCA(administrator, cainfo);
            
            CAInfo newInfo = remote.getCAInfo(administrator, caname);
            int caid = newInfo.getCAId();
            getOutputStream().println("CAId for created CA: " + caid);
              

            getOutputStream().println("-Created and published initial CRL.");
            getOutputStream().println("CA initialized");
        } catch (Exception e) {
        	debug("An error occured: ", e);
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
    private void initAuthorizationModule(int caid) throws Exception{
      getOutputStream().println("Initalizing Temporary Authorization Module.");  
      Context context = getInitialContext();
      IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);   
      IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();  
      authorizationsession.initialize(administrator, caid);
    } // initAuthorizationModule
}