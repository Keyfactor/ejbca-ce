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
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Shows info about a CA.
 *
 * @version $Id$
 */
public class CaInfoCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "info"; }
	public String getDescription() { return "Shows info about a CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        String cliUserName = "ejbca";
        String cliPassword = "ejbca";
        
        
        if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <caname>");
    		return;
        }
        try {
        	CryptoProviderTools.installBCProvider();
            String caname = args[1];
            ArrayList<Certificate> chain = new ArrayList<Certificate>(getCertChain(getAdmin(cliUserName, cliPassword), caname));
            CAInfo cainfo = getCAInfo(getAdmin(cliUserName, cliPassword), caname);
                                    
            getLogger().info("CA name: " + caname);
            getLogger().info("CA type: "+cainfo.getCAType());
            getLogger().info("CA ID: " + cainfo.getCAId());
            getLogger().info("CA CRL Expiration Period: " + cainfo.getCRLPeriod());
            getLogger().info("CA CRL Issue Interval: " + cainfo.getCRLIssueInterval());
            getLogger().info("CA Description: " + cainfo.getDescription());
            
            if (chain.size() < 2) {
            	getLogger().info("This is a Root CA.");
            } else {
            	getLogger().info("This is a subordinate CA.");
            }
              
            getLogger().info("Size of chain: " + chain.size());
            if (chain.size() > 0) {
                Certificate rootcert = chain.get(chain.size()-1);
                getLogger().info("Root CA DN: "+CertTools.getSubjectDN(rootcert));
                getLogger().info("Root CA id: "+CertTools.getSubjectDN(rootcert).hashCode());
                getLogger().info("Certificate valid from: "+CertTools.getNotBefore(rootcert));
                getLogger().info("Certificate valid to: "+CertTools.getNotAfter(rootcert));
                getLogger().info("Root CA key algorithm: "+rootcert.getPublicKey().getAlgorithm());
                getLogger().info("Root CA key size: "+KeyTools.getKeyLength(rootcert.getPublicKey()));
                if(rootcert.getPublicKey() instanceof ECPublicKey) {
                	if(((ECPublicKey) rootcert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                		getLogger().info("Root CA ECDSA key spec: " + ((ECNamedCurveSpec) ((ECPublicKey)rootcert.getPublicKey()).getParams()).getName());
                	}
                }
                for(int i = chain.size()-2; i>=0; i--){                                          
                    Certificate cacert = chain.get(i);
                    getLogger().info("CA DN: "+CertTools.getSubjectDN(cacert));
                    getLogger().info("Certificate valid from: "+CertTools.getNotBefore(cacert));
                    getLogger().info("Certificate valid to: "+CertTools.getNotAfter(cacert));
                    getLogger().info("CA key algorithm: "+cacert.getPublicKey().getAlgorithm());
                    getLogger().info("CA key size: "+KeyTools.getKeyLength(cacert.getPublicKey()));
                    if(cacert.getPublicKey() instanceof ECPublicKey) {
                    	if(((ECPublicKey) cacert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                    		getLogger().info("CA ECDSA key spec: " + ((ECNamedCurveSpec) ((ECPublicKey)cacert.getPublicKey()).getParams()).getName());
                    	}
                    }
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
