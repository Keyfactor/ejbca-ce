/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.protocol.ws.client;

import java.math.BigInteger;

import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Revokes a given certificate
 *
 * @version $Id$
 */
public class CheckRevokeStatusCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	private static final int ARG_ISSUERDN                 = 1;
	private static final int ARG_CERTSN                   = 2;

    /**
     * Creates a new instance of RevokeCertCommand
     *
     * @param args command line arguments
     */
    public CheckRevokeStatusCommand(String[] args) {
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
            if(args.length != 3){
            	usage();
            	System.exit(-1); // NOPMD, this is not a JEE app
            }
            
            String issuerdn = CertTools.stringToBCDNString(args[ARG_ISSUERDN]);            
            String certsn = getCertSN(args[ARG_CERTSN]);                                   
                   
            try{
            	
            	RevokeStatus status = getEjbcaRAWS().checkRevokationStatus(issuerdn,certsn);
            	if(status == null){
            		getPrintStream().println("Error, No certificate found in database.");
            	}else{
            		getPrintStream().println("Revocation status :");
            		getPrintStream().println("  IssuerDN      : " + status.getIssuerDN());
            		getPrintStream().println("  CertificateSN : " + status.getCertificateSN());
            		if(status.getReason() == RevokedCertInfo.NOT_REVOKED){
            			getPrintStream().println("  Status        : NOT REVOKED");
            		}else{
            			getPrintStream().println("  Status        : REVOKED");
            			getPrintStream().println("  Reason        : " + getRevokeReason(status.getReason()));
            			getPrintStream().println("  Date          : " + status.getRevocationDate().toString());
            		}
            	}
            }catch(AuthorizationDeniedException_Exception e){
            	getPrintStream().println("Error : " + e.getMessage());            
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

	private String getCertSN(String certsn) {
		try{
			new BigInteger(certsn,16);
		}catch(NumberFormatException e){
			getPrintStream().println("Error in Certificate SN");
			usage();
			System.exit(-1); // NOPMD, this is not a JEE app
		}
		return certsn;
	}

	protected void usage() {
		getPrintStream().println("Command used check the status of certificate");
		getPrintStream().println("Usage : checkrevocationstatus <issuerdn> <certificatesn (HEX)>  \n\n");

	}
}
