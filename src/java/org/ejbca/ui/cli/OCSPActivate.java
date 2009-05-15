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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.util.ConsolePasswordReader;

/**
 * Used to activate the external OCSP responder.
 * @author Lars Silven PrimeKey Solution AB
 * @version $Id$
 * 
 */
public class OCSPActivate extends ClientToolBox {

	private static final Logger log = Logger.getLogger(OCSPActivate.class);
	
	final String usage = "\n"
		+ getName() + " <hostname:port>\n"
		+ " Useed for HSM activation on an OCSP server install.\n"
		+ " hostname:port        the address of where the OCSP serrver is running. Only use 127.0.0.1 in a production environment.\n"
	    + "\nCheck ctb.log for messages.";

	/* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    void execute(String[] args) {
    	if (args.length<2) {
    		log.info(usage);
    		return;
    	}
    	String bindInfo = args[1];
    	char[] passwd = null;;
    	try {
    		ConsolePasswordReader console = new ConsolePasswordReader();
    		System.out.print("Password: ");
    		passwd = console.readPassword();
    	} catch (IOException e){
    		System.out.println("Problems reading password: '"+e.getMessage()+'\'');
    	}
        if (passwd != null) {
            try {
                final URL url = new URL("http://"+bindInfo+"/ejbca/publicweb/status/ocsp?activate="+new String(passwd));
                final HttpURLConnection con = (HttpURLConnection)url.openConnection();
                final int responseCode = con.getResponseCode();
                final String responseMessage = con.getResponseMessage();
                if (responseCode != 200) {
                    System.out.println("Unexpected result code " +responseCode+" for URL: '" + url.toString() + "'. Message was: '" + responseMessage+'\'');
                    return;
                }
                System.out.println("Password for keys sent to the OCSP responder. If the password was right the respnder will be activated. Check this.");
            } catch (IOException e){
                System.out.println("Network problems: '"+e.getMessage()+'\'');
            }        	
        }
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    String getName() {
        return "OCSPActivate";
    }
}
