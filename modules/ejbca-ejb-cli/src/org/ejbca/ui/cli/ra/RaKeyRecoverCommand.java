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
 
package org.ejbca.ui.cli.ra;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Set status to key recovery for a user's certificate.
 *
 * @version $Id$
 */
public class RaKeyRecoverCommand extends BaseRaAdminCommand {

    private CertificateStoreSessionRemote certificateStoreSession = ejb.getCertStoreSession();
    private RaAdminSessionRemote raAdminSession = ejb.getRAAdminSession();
    private KeyRecoverySessionRemote keyRecoverySession = ejb.getKeyRecoverySession();
    private UserAdminSessionRemote userAdminSession = ejb.getUserAdminSession();
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "keyrecover"; }
	public String getDescription() { return "Set status to key recovery for a user's certificate"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length != 3) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <CertificateSN (HEX)> <IssuerDN>");
                return;
            }
            BigInteger certificatesn = new BigInteger(args[1], 16);
            String issuerdn = args[2];
            boolean usekeyrecovery = raAdminSession.getCachedGlobalConfiguration(getAdmin()).getEnableKeyRecovery();  
            if(!usekeyrecovery){
            	getLogger().error("Keyrecovery have to be enabled in the system configuration in order to use this command.");
            	return;                   
            }   
            X509Certificate cert = (X509Certificate) certificateStoreSession.
            	findCertificateByIssuerAndSerno(getAdmin(), issuerdn, certificatesn);
            if(cert == null){
            	getLogger().error("Certificate couldn't be found in database.");
            	return;              
            }
            String username = certificateStoreSession.findUsernameByCertSerno(getAdmin(), certificatesn, issuerdn);
            if(!keyRecoverySession.existsKeys(getAdmin(),cert)){
            	getLogger().error("Specified keys doesn't exist in database.");
            	return;                  
            }
            if(keyRecoverySession.isUserMarked(getAdmin(),username)){
            	getLogger().error("User is already marked for recovery.");
            	return;                     
            }
            UserDataVO userdata = userAdminSession.findUser(getAdmin(), username);
            if(userdata == null){
            	getLogger().error("The user doesn't exist.");
            	return;
            }
            if (userAdminSession.prepareForKeyRecovery(getAdmin(), userdata.getUsername(), userdata.getEndEntityProfileId(), cert)) {
                getLogger().info("Keys corresponding to given certificate has been marked for recovery.");                           
            } else {
                getLogger().info("Failed to mark keys corresponding to given certificate for recovery.");                           
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
