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

import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * Dumps PEM or DER file as readable ASN1'
 * 
 * @version $Id$
 */
public class Asn1Dump extends BaseCommand {
	
	public String getMainCommand() { return null; }
	public String getSubCommand() { return "asn1dump"; }
	public String getDescription() { return "Dumps PEM or DER file as readable ASN1"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        if (args.length < 2) {
            getLogger().info("Usage: " + getCommand() + " <filename-of-pem-encoded-certs|filename-of-der-encoded-asn1>");
            return;
        }
    	try {
    		String filename = args[1];
    		boolean iscert = true;
    		Collection<Certificate> coll = null;
    		CryptoProviderTools.installBCProvider();
    		try {
        		coll = CertTools.getCertsFromPEM(filename);
        		if (coll.isEmpty()) {
        			iscert = false;
        		}
    		} catch (Exception e) {
    			iscert = false;
    		}
    		if (!iscert) {
        		ASN1InputStream ais = new ASN1InputStream(new FileInputStream(filename));
        		DERObject obj = ais.readObject();
        		String dump = ASN1Dump.dumpAsString(obj);
        		getLogger().info(dump);    			
    		} else {
        		Iterator<Certificate> iter = coll.iterator();
        		while (iter.hasNext()) {
        			Certificate cert = iter.next();
            		String dump = ASN1Dump.dumpAsString(cert);
            		getLogger().info(dump);    			
        		}
    		}
    	} catch (Exception e) {
    		throw new ErrorAdminCommandException(e);
    	}
    	
    }
}
