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

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists the names of all available CAs.
 *
 * @version $Id$
 */
public class CaListCAsCommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "listcas"; }
    @Override
    public String getDescription() { return "Lists the names of all available CAs"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
        	CryptoProviderTools.installBCProvider();
            Collection<Integer> caids = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCAs(getAdmin(cliUserName, cliPassword));
            Iterator<Integer> iter = caids.iterator();
            while (iter.hasNext()) {
                int caid = ((Integer)iter.next()).intValue();
                CAInfo ca = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), caid);
                Collection<Certificate> certs = ca.getCertificateChain();
                Iterator<Certificate> ci = certs.iterator();
                Certificate cacert = null;
                if (ci.hasNext()) {
                    cacert = (Certificate)ci.next();                	
                }
                getLogger().info("CA Name: "+ca.getName());
                getLogger().info(" Id: "+ca.getCAId());
                if (cacert != null) {
                	getLogger().info(" Issuer DN: "+CertTools.getIssuerDN(cacert));                	
                }
                getLogger().info(" Subject DN: "+ca.getSubjectDN());
                getLogger().info(" Type: "+ca.getCAType());
                getLogger().info(" Expire time: "+ca.getExpireTime());
                getLogger().info(" Signed by: "+ca.getSignedBy());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
