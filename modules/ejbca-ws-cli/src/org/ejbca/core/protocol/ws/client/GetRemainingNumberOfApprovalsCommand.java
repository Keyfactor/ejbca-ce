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

import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Checks how many approvals are remaining to approva on an approval request
 *
 * @version $Id$
 */
public class GetRemainingNumberOfApprovalsCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

	private static final int ARG_REQUESTID = 1;

	/**
	 * Creates a new instance
	 *
	 * @param args command line arguments
	 */
	public GetRemainingNumberOfApprovalsCommand(String[] args) {
		super(args);
	}

	@Override
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			if (this.args.length < 2) {
	            usage();
				System.exit(-1); // NOPMD, it's not a JEE app
			}
			final int requestID = Integer.valueOf(this.args[ARG_REQUESTID]);
			try{
				final int result =  getEjbcaRAWS().getRemainingNumberOfApprovals(requestID);
                getPrintStream().println("Approvals remaining: " + result);
			} catch (AuthorizationDeniedException_Exception e) {
				getPrintStream().println("Error : " + e.getMessage());
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	@Override
	protected void usage() {
		getPrintStream().println("Command used to check if there are approvals remaining for a specified approval request.");
		getPrintStream().println("The requestID is a unique key for each approval request, and is for example returned as part of a WaitingForApprovalException when calling the EditUser command, if approvals are required to add/edit an end entity.");
		getPrintStream().println("Usage : getremainingnumberofapprovals <requestID>");
	}
}
