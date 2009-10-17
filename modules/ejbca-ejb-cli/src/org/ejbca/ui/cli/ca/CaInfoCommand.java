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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;

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
        if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <caname>");
    		return;
        }
        try {            
            String caname = args[1];
            ArrayList chain = new ArrayList(getCertChain(caname));
            CAInfo cainfo = getCAInfo(caname);
                                    
            getLogger().info("CA name: " + caname);
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
                X509Certificate rootcert = (X509Certificate)chain.get(chain.size()-1);
                getLogger().info("Root CA DN: "+CertTools.getSubjectDN(rootcert));
                getLogger().info("Root CA id: "+CertTools.getSubjectDN(rootcert).hashCode());
                getLogger().info("Certificate valid from: "+rootcert.getNotBefore().toString());
                getLogger().info("Certificate valid to: "+rootcert.getNotAfter().toString());
                if(rootcert.getPublicKey() instanceof JCEECPublicKey) {
                	if(((JCEECPublicKey) rootcert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                		getLogger().info("Root CA ECDSA key spec: " + ((ECNamedCurveSpec) ((JCEECPublicKey) rootcert.getPublicKey()).getParams()).getName());
                	}
                } else {
                	getLogger().info("Root CA keysize: "+getKeyLength(rootcert.getPublicKey()));
                }
                for(int i = chain.size()-2; i>=0; i--){                                          
                    X509Certificate cacert = (X509Certificate)chain.get(i);
                    getLogger().info("CA DN: "+CertTools.getSubjectDN(cacert));
                    getLogger().info("Certificate valid from: "+cacert.getNotBefore().toString());
                    getLogger().info("Certificate valid to: "+cacert.getNotAfter().toString());
                    if(cacert.getPublicKey() instanceof JCEECPublicKey) {
                    	if(((JCEECPublicKey) cacert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                    		getLogger().info("CA ECDSA key spec: " + ((ECNamedCurveSpec) ((JCEECPublicKey) cacert.getPublicKey()).getParams()).getName());
                    	}
                    } else {
                    	getLogger().info("CA keysize: "+getKeyLength(rootcert.getPublicKey()));
                    }
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
    
    private static int getKeyLength(PublicKey key) {
    	if(key instanceof RSAPublicKey) {
    		return ((RSAPublicKey) key).getModulus().bitLength();
    	} else if(key instanceof DSAPublicKey) {
    		return ((DSAPublicKey) key).getY().bitLength();
    	}
    	return 0;
    }
}
