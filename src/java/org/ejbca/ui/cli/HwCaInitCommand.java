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

import java.io.PrintWriter;
import java.io.StringWriter;
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
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.KeyStrings;
import org.ejbca.core.model.ca.catoken.NFastCAToken;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;


/**
 * Inits the CA by creating the first CRL and publiching the CRL and CA certificate.
 *
 * @version $Id$
 */
public class HwCaInitCommand extends BaseCaAdminCommand {

    /**
     * Creates a new instance of CaInitCommand
     *
     * @param args command line arguments
     */
    public HwCaInitCommand(String[] args) {
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
        final String DEFAULT_KEY = "default";
        final String SIGN_KEY = "sign";
        if (this.args.length < 7) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            pw.println("Used to create a Root CA using RSA keys.");
            pw.println("Usage: "+this.args[0] + " " + this.args[1] +" <caname> <dn> <validity-days>");
            pw.close();
            throw new IllegalAdminCommandException(sw.toString());
        }

        try {             	
            final String caname = this.args[4];
            final String dn = StringTools.strip(CertTools.stringToBCDNString(this.args[5]));
            final int validity = Integer.parseInt(this.args[6]);
            byte keyStoreID[];{
                KeyStoreContainer ksc = new KeyStoreContainer(this.args[3],this.args[2], this.args.length>7 ? this.args[7] : null);
                ksc.generate(2048, DEFAULT_KEY);
                ksc.generate(2048, SIGN_KEY);
                keyStoreID = ksc.storeKeyStore();
            }
            getOutputStream().println("Initializing CA");            
            
            getOutputStream().println("Generating rootCA keystore:");
            getOutputStream().println("CA name: "+caname);
            getOutputStream().println("DN: "+dn);
            getOutputStream().println("Validity (days): "+validity);
                            
            initAuthorizationModule(dn.hashCode());

            HardCATokenInfo catokeninfo = new HardCATokenInfo();
            catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
            {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                pw.println(KeyStrings.CAKEYPURPOSE_DEFAULT_STRING+" "+DEFAULT_KEY);
                pw.println(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING+" "+SIGN_KEY);
                pw.println(NFastCAToken.SLOT_LABEL_KEY+" "+new String(keyStoreID));
                pw.close();
                catokeninfo.setProperties(sw.toString());
            }
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
                                             true, // Finish User
                                             new ArrayList(),
			                                 false, // use default utf8 settings
			                                 new ArrayList(), // Approvals Settings
			                                 1, // Number of Req approvals
			                                 false); // Use UTF8 subject DN by default       
            
            getOutputStream().println("Creating CA...");
            ICAAdminSessionRemote remote = getCAAdminSessionRemote();
            remote.createCA(this.administrator, cainfo);
            
            CAInfo newInfo = remote.getCAInfo(this.administrator, caname);
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
      authorizationsession.initialize(this.administrator, caid);
    } // initAuthorizationModule
}