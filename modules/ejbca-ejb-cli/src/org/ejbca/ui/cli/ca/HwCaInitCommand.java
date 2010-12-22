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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.KeyStrings;
import org.ejbca.core.model.ca.catoken.NFastCAToken;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerFactory;

/**
 * Create a CA and its first CRL. Publishes the CRL and CA certificate
 *
 * @version $Id$
 */
// TODO: Is this really used???? The arguments does not to be in synch with the description..
public class HwCaInitCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "inithw"; }
	public String getDescription() { return "(Deprecated) Create a CA and its first CRL. Publishes the CRL and CA certificate"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
    	// Create new CA.
        final String DEFAULT_KEY = "default";
        final String SIGN_KEY = "sign";
        if (args.length < 7) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <caname> <dn> <validity-days>");	// This really cannot be right!!!
            return;
        }

        try {             	
            final String caname = args[5];
            final String dn = CertTools.stringToBCDNString(StringTools.strip(args[6]));
            final int validity = Integer.parseInt(args[7]);
            HardCATokenInfo catokeninfo = new HardCATokenInfo();
            byte keyStoreID[];{
                KeyStoreContainer ksc = KeyStoreContainerFactory.getInstance(args[4],args[2], args[3], args.length>8 ? args[8] : null, null, null);
                ksc.generate("2048", DEFAULT_KEY);
                ksc.generate("2048", SIGN_KEY);
                keyStoreID = ksc.storeKeyStore();
                catokeninfo.setAuthenticationCode(new String(ksc.getPassPhraseGetSetEntry()));
            }
            getLogger().info("Initializing CA");            
            getLogger().info("Generating rootCA keystore:");
            getLogger().info("CA name: "+caname);
            getLogger().info("DN: "+dn);
            getLogger().info("Validity (days): "+validity);
                            
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                pw.println(KeyStrings.CAKEYPURPOSE_DEFAULT_STRING+" "+DEFAULT_KEY);
                pw.println(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING+" "+SIGN_KEY);
                pw.println(NFastCAToken.SLOT_LABEL_KEY+" "+new String(keyStoreID));
                pw.close();
                catokeninfo.setProperties(sw.toString());
            }
            catokeninfo.setClassPath(org.ejbca.core.model.ca.catoken.NFastCAToken.class.getName());
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
                                             null, // PolicyId
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
                                             new ArrayList(),
			                                 false, // use default utf8 settings
			                                 new ArrayList(), // Approvals Settings
			                                 1, // Number of Req approvals
			                                 false, // Use UTF8 subject DN by default
			                                 true, // Use LDAP DN order by default
			                                 false, // Use CRL Distribution Point on CRL
			                                 false,  // CRL Distribution Point on CRL critical
			                                 true, // Include in Health Check
			                                 true, // isDoEnforceUniquePublicKeys
			                                 true, // isDoEnforceUniqueDistinguishedName
			                                 false, // isDoEnforceUniqueSubjectDNSerialnumber
			                                 true, // useCertReqHistory
			                                 true, // useUserStorage
			                                 true, // useCertificateStorage
			                                 null //cmpRaAuthSecret
			                                 );
            
            getLogger().info("Creating CA...");
            ejb.getCAAdminSession().createCA(getAdmin(), cainfo);
            
            CAInfo newInfo = ejb.getCAAdminSession().getCAInfo(getAdmin(), caname);
            int caid = newInfo.getCAId();
            getLogger().info("CAId for created CA: " + caid);
            getLogger().info("-Created and published initial CRL.");
            getLogger().info("CA initialized");
        } catch (Exception e) {
        	getLogger().debug("An error occured: ", e);
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    

}