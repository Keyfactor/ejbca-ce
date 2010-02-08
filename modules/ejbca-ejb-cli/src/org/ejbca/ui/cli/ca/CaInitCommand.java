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

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Create a CA and its first CRL. Publishes the CRL and CA certificate
 *
 * @version $Id$
 */
public class CaInitCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "init"; }
	public String getDescription() { return "Create a CA and its first CRL. Publishes the CRL and CA certificate"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        // Create new CA.
        if (args.length < 7) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <caname> <dn> <catokentype> <catokenpassword> <keyspec> <keytype> <validity-days> <policyID> <signalgorithm> [<catokenproperties> or null] [<signed by caid>]");
    		getLogger().info(" catokentype defines if the CA should be created with soft keys or on a HSM. Use 'soft' for software keys and 'org.ejbca.core.model.ca.catoken.PKCS11CAToken' for PKCS#11 HSMs.");
    		getLogger().info(" catokenpassword is the password for the CA token. Set to 'null' to use the default system password for Soft token CAs");
    		getLogger().info(" keytype is RSA, DSA or ECDSA.");
    		getLogger().info(" keyspec for RSA keys is size of RSA keys (1024, 2048, 4096).");
    		getLogger().info(" keyspec for DSA keys is size of DSA keys (1024).");
    		getLogger().info(" keyspec for ECDSA keys is name of curve or 'implicitlyCA', see docs.");
    		getLogger().info(" policyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' or objectID and cpsurl as \"2.5.29.32.0 http://foo.bar.com/mycps.txt\".");
    		String availableSignAlgs = "";
    		for (String algorithm : AlgorithmConstants.AVAILABLE_SIGALGS) {
    			availableSignAlgs += (availableSignAlgs.length()==0?"":", ") + algorithm;
    		}
    		getLogger().info(" signalgorithm is on of " + availableSignAlgs);
    		getLogger().info(" catokenproperties is a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in admin gui.");
    		getLogger().info(" signed by caid is the CA id of a CA that will sign this CA. If this is omitted the new CA will be self signed (i.e. a root CA).");
    		return;
        }
            
        try {             	
            final String caname = args[1];
            final String dn = StringTools.strip(CertTools.stringToBCDNString(args[2]));
            final String catokentype = args[3];
            final String catokenpassword = StringTools.passwordDecryption(args[4], "ca.tokenpassword");
            final String keyspec = args[5];
            final String keytype = args[6];
            final int validity = Integer.parseInt(args[7]);
            String policyId = args[8];
            final ArrayList policies = new ArrayList(1);
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
            	getLogger().warn("WARNING!");
            	getLogger().warn("WARNING: Using exportable strength crypto!");
            	getLogger().warn("WARNING!");
            	getLogger().warn("The Unlimited Strength Crypto policy files have not been installed. EJBCA may not function correctly using exportable crypto.");
            	getLogger().warn("Please install the Unlimited Strength Crypto policy files as documented in the Installation guide.");
            	getLogger().warn("Sleeping 10 seconds...");
            	getLogger().warn("");
            	Thread.sleep(10000);
            }
            getLogger().info("Initializing CA");            
            
            getLogger().info("Generating rootCA keystore:");
            getLogger().info("CA name: "+caname);
            getLogger().info("DN: "+dn);
            getLogger().info("CA token type: "+catokentype);
            getLogger().info("CA token password: "+catokenpassword);
            getLogger().info("Keytype: "+keytype);
            getLogger().info("Keyspec: "+keyspec);
            getLogger().info("Validity (days): "+validity);
            getLogger().info("Policy ID: "+policyId);
            getLogger().info("Signature alg: "+signAlg);
            getLogger().info("CA token properties: "+catokenproperties);
            getLogger().info("Signed by: "+(signedByCAId == CAInfo.SELFSIGNED ? "self signed " : signedByCAId));
            if (signedByCAId != CAInfo.SELFSIGNED) {
            	CAInfo signedBy = getCAAdminSession().getCAInfo(getAdmin(), signedByCAId);
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
	            softcatokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
	            softcatokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
	            catokeninfo = softcatokeninfo;
            } else {
            	HardCATokenInfo hardcatokeninfo = new HardCATokenInfo();
            	hardcatokeninfo.setAuthenticationCode(catokenpassword);
            	hardcatokeninfo.setCATokenStatus(ICAToken.STATUS_ACTIVE);
            	hardcatokeninfo.setClassPath(catokentype);
            	hardcatokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            	hardcatokeninfo.setProperties(catokenproperties);
            	hardcatokeninfo.setSignatureAlgorithm(signAlg);
            	catokeninfo = hardcatokeninfo;
            }
            
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            String keySpec = keyspec;
            if (keytype.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
            	// Never use larger keys than 2048 bit RSA for OCSP signing
            	int len = Integer.parseInt(keySpec);
            	if (len > 2048) {
            		keySpec = "2048";				 
            	}
            }
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(
                    new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                                          "CN=XKMSCertificate, " + dn,
                                          "",
                                          keySpec,
                                          keytype));
            extendedcaservices.add(
                    new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                                          "CN=CmsCertificate, " + dn,
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
            
            getLogger().info("Creating CA...");
            getCAAdminSession().createCA(getAdmin(), cainfo);
            
            CAInfo newInfo = getCAAdminSession().getCAInfo(getAdmin(), caname);
            int caid = newInfo.getCAId();
            getLogger().info("CAId for created CA: " + caid);
            getLogger().info("-Created and published initial CRL.");
            getLogger().info("CA initialized");
        } catch (Exception e) {
        	getLogger().debug("An error occured: ", e);
            throw new ErrorAdminCommandException(e);
        }
    }
    
    private void initAuthorizationModule(int caid) throws Exception{
    	getLogger().info("Initalizing Temporary Authorization Module.");  
      getAuthorizationSession().initialize(getAdmin(), caid);
    }
}
