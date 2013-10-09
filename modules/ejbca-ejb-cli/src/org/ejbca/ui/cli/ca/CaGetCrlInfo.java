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

import java.util.Collection;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ValidityDate;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * List information about the latest CRL from each CA.
 *
 * @version $Id$
 */
public class CaGetCrlInfo extends BaseCaAdminCommand {

    @Override
    public String getSubCommand() { return "getcrlinfo"; }
    @Override
    public String getDescription() { return "List information about latest CRLs"; }

	@Override
	public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
	    
        try {
        	Collection<Integer> caIds = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCAs(getAuthenticationToken(cliUserName, cliPassword));
        	for (Integer caId : caIds) {
        		final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caId);
        		final StringBuilder sb = new StringBuilder();
        		sb.append("\"").append(cainfo.getName()).append("\" \"").append(cainfo.getSubjectDN()).append("\"");
        		final CRLInfo crlInfo = ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLInfo(cainfo.getSubjectDN(), false);
        		if (crlInfo != null) {
            		sb.append(" CRL# ").append(crlInfo.getLastCRLNumber());
            		sb.append(" issued ").append(ValidityDate.formatAsUTC(crlInfo.getCreateDate()));
            		sb.append(" expires ").append(ValidityDate.formatAsUTC(crlInfo.getExpireDate()));
        		} else {
        			sb.append(" NO_CRL_ISSUED");
        		}
        		final CRLInfo deltaCrlInfo = ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLInfo(cainfo.getSubjectDN(), true);
        		if (deltaCrlInfo!=null) {
            		sb.append(" DELTACRL# ").append(deltaCrlInfo.getLastCRLNumber());
            		sb.append(" issued ").append(ValidityDate.formatAsUTC(deltaCrlInfo.getCreateDate()));
            		sb.append(" expires ").append(ValidityDate.formatAsUTC(deltaCrlInfo.getExpireDate()));
        		} else {
        			sb.append(" NO_DELTACRL_ISSUED");
        		}
        		getLogger().info(sb.toString());
        	}
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);
        }        	
	}
}
