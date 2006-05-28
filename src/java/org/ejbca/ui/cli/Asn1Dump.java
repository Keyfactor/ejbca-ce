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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.ejbca.util.CertTools;


/**
 * Implements the CA command line interface
 *
 * @version $Id: Asn1Dump.java,v 1.1 2006-05-28 14:51:20 anatom Exp $
 */
public class Asn1Dump extends BaseCommand {
	
	public Asn1Dump(String[] args) {
        this.args = args;
	}
	
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            if (args.length == 1) {
            	Asn1Dump d = new Asn1Dump(args);
            	d.execute();
            } else {
                System.out.println(
                    "Usage: asn1dump filename-of-pem-encoded-certs||filename-of-der-encoded-asn1");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            //e.printStackTrace();
            System.exit(-1);
        }
    }
    
    public void execute() throws ErrorAdminCommandException {
    	try {
    		String filename = args[0];
    		boolean iscert = true;
    		Collection coll = null;
    		CertTools.installBCProvider();
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
        		getOutputStream().println(dump);    			
    		} else {
        		Iterator iter = coll.iterator();
        		while (iter.hasNext()) {
        			X509Certificate cert = (X509Certificate)iter.next();
            		String dump = ASN1Dump.dumpAsString(cert);
            		getOutputStream().println(dump);    			
        		}
    		}
    	} catch (Exception e) {
    		throw new ErrorAdminCommandException(e);
    	}
    	
    }
}


//ca
