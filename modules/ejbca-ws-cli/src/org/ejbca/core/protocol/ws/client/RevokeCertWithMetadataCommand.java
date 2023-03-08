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
import java.util.ArrayList;
import java.util.List;

import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyValuePair;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Revokes a given certificate. Difference with normal RevokeCertCommand is that 
 * this one here allows to include a list of keyvaluepair input parameters
 * for example "reason=REV_SUPERSEDED" "certificateProfileId=12"
 *
 * @version $Id: RevokeCertWithMetadataCommand.java 28395 2018-02-27 14:19:00Z tarmo_r_helmes $
 */
public class RevokeCertWithMetadataCommand extends EJBCAWSRABaseCommand implements IAdminCommand {


	private static final int ARG_ISSUERDN			= 1;
	private static final int ARG_CERTSN				= 2;

	private static final String REASON_KEY = "reason";

	/**
	 * Creates a new instance of RevokeCertCommand
	 *
	 * @param args command line arguments
	 */
	public RevokeCertWithMetadataCommand(String[] args) {
		super(args);
	}
	
	@Override
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			if(this.args.length < 3) {
				usage();
				System.exit(-1); // NOPMD, it's not a JEE app
			}

			List<KeyValuePair> metadata = parseInputArgs();

			final String issuerdn = CertTools.stringToBCDNString(this.args[ARG_ISSUERDN]);
			final String certsn = getCertSN(this.args[ARG_CERTSN]);

			final String justRevoke = "To revoke the certificate with the current time remove the last argument (revocation time).";

			try {
				final RevokeStatus status = getEjbcaRAWS().checkRevokationStatus(issuerdn, certsn);
				if (status != null) {
					getEjbcaRAWS().revokeCertWithMetadata(issuerdn, certsn, metadata);
					getPrintStream().println("Certificate revoked (or unrevoked) successfully.");
				} else {
					getPrintStream().println("Certificate does not exist.");
				}
			} catch (AuthorizationDeniedException_Exception e) {
				getPrintStream().println("Error : " + e.getMessage());
			} catch (AlreadyRevokedException_Exception e) {
				getPrintStream().println("The certificate was already revoked, or you tried to unrevoke a permanently revoked certificate.");
			} catch (WaitingForApprovalException_Exception e) {
				getPrintStream().println("The revocation request has been sent for approval.");
			} catch (ApprovalException_Exception e) {
				getPrintStream().println("This revocation has already been requested.");
			} catch (RevokeBackDateNotAllowedForProfileException_Exception e) {
				getPrintStream().println(e.getMessage());
				getPrintStream().println(justRevoke);
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	protected List<KeyValuePair> parseInputArgs() throws Exception {
		List<KeyValuePair> metadata = new ArrayList<>();
		if (this.args.length > 3) {
            for (int i=3; i<this.args.length; i++) {
                String arg = this.args[i];
                String[] parts = arg.split("=", 2);

                if (parts.length != 2) {
                    String msg = "Problem with parameter: " + arg + ". Invalid format, please use \"key=value\"";
                    getPrintStream().println(msg);
                    throw new IllegalArgumentException(msg);
                }
                KeyValuePair keyValuePair = new KeyValuePair();
                String key = parts[0];
                keyValuePair.setKey(key);

                if (key.equalsIgnoreCase(REASON_KEY)) {
                    final int reason = getRevokeReason(parts[1]);
                    keyValuePair.setValue(Integer.valueOf(reason).toString());
                } else {
                    keyValuePair.setValue(parts[1]);
                }
                metadata.add(keyValuePair);
            }
        }
		return metadata;
	}


	private String getCertSN(String certsn) {
		try {
			new BigInteger(certsn, 16);
		} catch(NumberFormatException e) {
			getPrintStream().println("Error in Certificate SN");
			usage();
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		return certsn;
	}

	@Override
	protected void usage() {
		getPrintStream().println("Command used to revoke or unrevoke a certificate.");
		getPrintStream().println("Unrevocation is done using the reason REV_REMOVEFROMCRL, and can only be done if the certificate is revoked with reason REV_CERTIFICATEHOLD.");
		getPrintStream().println("Usage : revokecert <issuerdn> <certificatesn(HEX)> reason=<reason> [revocationdate=<revocation date>] [certificateProfileId=<certificateProfileId>]");
		getPrintStream().println();
		getPrintStream().println();
		getPrintStream().println("Reason should be one of : ");
		for(int i=1; i< REASON_TEXTS.length-1;i++){
			getPrintStream().print(REASON_TEXTS[i] + ", ");
		}
		getPrintStream().print(REASON_TEXTS[REASON_TEXTS.length-1]);
		getPrintStream().println();
		getPrintStream().println("Revocation date is optional. If specified it must be in the past and must be a valid ISO8601 string");
		getPrintStream().println("Example: 2012-06-07T23:55:59+02:00");
		getPrintStream().println("Certificate profile id is optional.");
	}


}
