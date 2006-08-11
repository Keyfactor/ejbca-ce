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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.naming.InitialContext;

import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.model.ra.UserDataConstants;

/**
 * Find details of a user in the database.
 *
 * @version $Id: RaKeyRecoverCommand.java,v 1.2 2006-08-11 04:17:43 herrvendil Exp $
 */
public class RaKeyRecoverCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaFindUserCommand
     *
     * @param args command line arguments
     */
    public RaKeyRecoverCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length != 3) {
                getOutputStream().println("Usage: RA keyrecover <CertificateSN (HEX)> <IssuerDN>");

                return;
            }

            //InitialContext jndicontext = new InitialContext();
            InitialContext jndicontext = getInitialContext();

            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

            obj1 = jndicontext.lookup("KeyRecoverySession");

            IKeyRecoverySessionHome keyrecoverysessionhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "KeyRecoverySession"), IKeyRecoverySessionHome.class);
            IKeyRecoverySessionRemote keyrecoverysession = keyrecoverysessionhome.create();

            BigInteger certificatesn = new BigInteger(args[1], 16);
            String issuerdn = args[2];

             boolean usekeyrecovery = getRaAdminSession().loadGlobalConfiguration(administrator).getEnableKeyRecovery();  
             if(!usekeyrecovery){
               getOutputStream().println("Keyrecovery have to be enabled in the system configuration in order to use this command.");
               return;                   
             }   
              
             X509Certificate cert = (X509Certificate) certificatesession.findCertificateByIssuerAndSerno(
                                                                             administrator, issuerdn, 
                                                                             certificatesn);
              
             if(cert == null){
               getOutputStream().println("Certificate couldn't be found in database.");
               return;              
             }
              
             String username = certificatesession.findUsernameByCertSerno(administrator, certificatesn, issuerdn);
              
             if(!keyrecoverysession.existsKeys(administrator,cert)){
               getOutputStream().println("Specified keys doesn't exist in database.");
               return;                  
             }
              
             if(keyrecoverysession.isUserMarked(administrator,username)){
               getOutputStream().println("User is already marked for recovery.");
               return;                     
             }
  
             keyrecoverysession.markAsRecoverable(administrator, 
                                                  cert);
        
             getAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_KEYRECOVERY,false); 
 
             getOutputStream().println("Keys corresponding to given certificate has been marked for recovery.");                           

        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
