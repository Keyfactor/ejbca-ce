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
import java.security.cert.Certificate;

import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;

/**
 * Revokes a certificate in the database.
 *
 * @version $Id$
 */
public class RaRevokeCertCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "revokecert"; }
	public String getDescription() { return "Revokes a certificate"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 4) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <issuerDN> <cert serial number in hex> <reason>");
                getLogger().info(" Reason: unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3)," +
                		" superseded(4), cessationOfOperation(5), certficateHold(6), removeFromCRL(8),privilegeWithdrawn(9),aACompromise(10)");
                getLogger().info(" Normal reason is 0");
                return;
            }
            final String issuerDNStr = args[1];
            final String issuerDN = CertTools.stringToBCDNString(issuerDNStr);
            final String certserno = args[2];
            final BigInteger serno;
            try {
                serno = new BigInteger(certserno, 16);            	
            } catch (NumberFormatException e) {
            	throw new ErrorAdminCommandException("Invalid hexadecimal certificate serial number string: "+certserno);
            }
            int reason = Integer.parseInt(args[3]);
            if ((reason == 7) || (reason < 0) || (reason > 10)) {
            	getLogger().error("Reason must be an integer between 0 and 10 except 7.");
            } else {
                Certificate cert = ejb.getCertStoreSession().findCertificateByIssuerAndSerno(getAdmin(), issuerDN, serno);
                if (cert != null) {
                    getLogger().info("Found certificate:");
                    getLogger().info("Subject DN=" + CertTools.getSubjectDN(cert));
                    // We need the user this cert is connected with
        			// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
        			// that was permanently revoked
        			try {
            			ejb.getUserAdminSession().revokeCert(getAdmin(), serno, issuerDN, reason);
                        getLogger().info( (reason == 8 ? "Unrevoked":"Revoked") + " certificate with issuerDN '"+issuerDN+"' and serialNumber "+certserno+". Revocation reason="+reason);        				
                    } catch (AlreadyRevokedException e) {
                    	if (reason == 8) {
                            getLogger().info("Certificate with issuerDN '"+issuerDN+"' and serialNumber "+certserno+" is not revoked, nothing was done.");                    		
                    	} else {
                            getLogger().info("Certificate with issuerDN '"+issuerDN+"' and serialNumber "+certserno+" is already revoked, nothing was done.");
                    	}
                        getLogger().info(e.getMessage());        				
                    }
                } else {
                    getLogger().info("No certificate found with issuerDN '"+issuerDN+"' and serialNumber "+certserno);                    	
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
