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
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * Inits the CA by creating the CA, the first CRL, and publishing the CRL and CA certificate.
 *
 * @version $Id$
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
           String msg = "Used to create a Root CA.";
           msg += "\nUsage: CA init <caname> <dn> <catokentype> <catokenpassword> <keyspec> <keytype> <validity-days> <policyID> <signalgorithm> [<catokenproperties> or null] [<signed by caid>]";
           msg += "\ncatokentype defines if the CA should be created with soft keys or on a HSM. Use soft for software keys and org.ejbca.core.model.ca.catoken.PKCS11CAToken for PKCS#11 HSMs.";
           msg += "\ncatokenpassword is the password for the CA token. Set to 'null' to use the default system password for Soft token CAs";
           msg += "\nkeytype is RSA, DSA or ECDSA.";
           msg += "\nkeyspec for RSA keys is size of RSA keys (1024, 2048, 4096).";
           msg += "\nkeyspec for DSA keys is size of DSA keys (1024).";
           msg += "\nkeyspec for ECDSA keys is name of curve or 'implicitlyCA', see docs.";
           msg += "\npolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' or objectID and cpsurl as \"2.5.29.32.0 http://foo.bar.com/mycps.txt\".";
           msg += "\nsignalgorithm is SHA1WithRSA, SHA1WithDSA or SHA1WithECDSA.";
           msg += "\ncatokenproperties is a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in admin gui.";
           msg += "\nsigned by caid is the CA id of a CA that will sign this CA. If this is omitted the new CA will be self signed (i.e. a root CA).";
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
            	policies.add(new CertificatePolicy(id, CertificatePolicy.id_qt_cps, cpsurl));
            }
            String signAlg = args[9];
            String catokenproperties = null;
            if (args.length > 10 && !"soft".equals(catokentype)) {
            	String filename = args[10];
            	if ( (filename != null) && (!filename.equalsIgnoreCase("null")) ) {
                	if (!(new File(filename)).exists()) {
                		throw new IllegalAdminCommandException("File " + filename + " does not exist");
                	}
                    catokenproperties = new String(FileTools.readFiletoBuffer(filename));            		
            	}
            }
            int signedByCAId = CAInfo.SELFSIGNED; 
            if (args.length > 11) {
            	String caid = args[11];
            	signedByCAId= Integer.valueOf(caid);
            }

                        
            if (KeyTools.isUsingExportableCryptography()) {
            	getOutputStream().println("WARNING!");
            	getOutputStream().println("WARNING: Using exportable strength crypto!");
            	getOutputStream().println("WARNING!");
            	getOutputStream().println("The Unlimited Strength Crypto policy files have not been installed. EJBCA may not function correctly using exportable crypto.");
            	getOutputStream().println("Please install the Unlimited Strength Crypto policy files as documented in the Installation guide.");
            	getOutputStream().println("Sleeping 10 seconds...");
            	getOutputStream().println();
            	Thread.sleep(10000);
            }
            getOutputStream().println("Initializing CA");            
            
            getOutputStream().println("Generating rootCA keystore:");
            getOutputStream().println("CA name: "+caname);
            getOutputStream().println("DN: "+dn);
            getOutputStream().println("CA token type: "+catokentype);
            getOutputStream().println("CA token password: "+catokenpassword);
            getOutputStream().println("Keytype: "+keytype);
            getOutputStream().println("Keyspec: "+keyspec);
            getOutputStream().println("Validity (days): "+validity);
            getOutputStream().println("Policy ID: "+policyId);
            getOutputStream().println("Signature alg: "+signAlg);
            getOutputStream().println("CA token properties: "+catokenproperties);
            getOutputStream().println("Signed by: "+(signedByCAId == CAInfo.SELFSIGNED ? "self signed " : signedByCAId));
            if (signedByCAId != CAInfo.SELFSIGNED) {
            	CAInfo signedBy = getCAAdminSession().getCAInfo(administrator, signedByCAId);
            	if (signedBy == null) {
                	throw new IllegalArgumentException("CA with id "+signedByCAId+" does not exist.");            		
            	}
            }
                            
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
                                             signedByCAId,
                                             (Collection) null,
                                             catokeninfo,
                                             "Initial CA",
                                             -1, null,
                                             policies, // PolicyId
                                             24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
                                             0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssueInterval
                                             10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLOverlapTime
                                             0 * SimpleTime.MILLISECONDS_PER_HOUR, // DeltaCRLPeriod
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
			                                 true, // Use LDAP DN order by default
			                                 false, // Use CRL Distribution Point on CRL
			                                 false,  // CRL Distribution Point on CRL critical
			                                 true // include in health check
			                                 );
            
            getOutputStream().println("Creating CA...");
            getCAAdminSession().createCA(administrator, cainfo);
            
            CAInfo newInfo = getCAAdminSession().getCAInfo(administrator, caname);
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
      getAuthorizationSession().initialize(administrator, caid);
    } // initAuthorizationModule
}