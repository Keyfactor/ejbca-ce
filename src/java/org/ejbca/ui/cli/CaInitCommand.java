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

import java.util.ArrayList;
import java.util.Collection;

import javax.naming.Context;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;


/**
 * Inits the CA by creating the first CRL and publiching the CRL and CA certificate.
 *
 * @version $Id: CaInitCommand.java,v 1.4 2006-06-06 17:14:30 anatom Exp $
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
        if (args.length < 6) {
           String msg = "Used to create a Root CA.";
           msg += "\nUsage: CA init <caname> <dn> <keysize> <validity-days> <policyID>";
           msg += "\npolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0'.";
           throw new IllegalAdminCommandException(msg);
        }
            
        try {             	
            String caname = args[1];
            String dn = CertTools.stringToBCDNString(args[2]);
            dn = StringTools.strip(dn);
            int keysize = Integer.parseInt(args[3]);
            int validity = Integer.parseInt(args[4]);
            String policyId = args[5];
            if (policyId.equals("null"))
              policyId = null;
              
            getOutputStream().println("Initializing CA");            
            ICAAdminSessionRemote caadminsession = getCAAdminSessionRemote();
            
            getOutputStream().println("Generating rootCA keystore:");
            getOutputStream().println("CA name: "+caname);
            getOutputStream().println("DN: "+dn);
            getOutputStream().println("Keysize: "+keysize);
            getOutputStream().println("Validity (days): "+validity);
            getOutputStream().println("Policy ID: "+policyId);
                            
            initAuthorizationModule(dn.hashCode());

                       
            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setKeySize(keysize);
            catokeninfo.setAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(
              new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                                    "CN=OCSPSignerCertificate, " + dn,
                                    "",
                                    2048,
                                    OCSPCAServiceInfo.KEYALGORITHM_RSA));
              
            
            X509CAInfo cainfo = new X509CAInfo(dn, 
                                             caname, SecConst.CA_ACTIVE,
                                             "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                                             validity, 
                                             null, // Expiretime                                             
                                             CAInfo.CATYPE_X509,
                                             CAInfo.SELFSIGNED,
                                             (Collection) null,
                                             catokeninfo,
                                             "Initial CA",
                                             -1, null,
                                             policyId, // PolicyId
                                             24, // CRLPeriod
                                             0, // CRLIssueInterval
                                             10, // CRLOverlapTime
                                             new ArrayList(),
                                             true, // Authority Key Identifier
                                             false, // Authority Key Identifier Critical
                                             true, // CRL Number
                                             false, // CRL Number Critical
                                             "", // Default CRL Dist Point
                                             "", // Default OCSP Service Locator
                                             true, // Finish User
                                             extendedcaservices,
			                                 false // use default utf8 settings
			                                 );         
            
            getOutputStream().println("Creating CA...");
            caadminsession.createCA(administrator, cainfo);
            
            int caid = caadminsession.getCAInfo(administrator, caname).getCAId();
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