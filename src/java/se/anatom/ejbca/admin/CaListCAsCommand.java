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
 
package se.anatom.ejbca.admin;

import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;

/**
 * Lists the names of all available CAs.
 *
 * @version $Id: CaListCAsCommand.java,v 1.3 2004-10-13 07:14:46 anatom Exp $
 */
public class CaListCAsCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaListCAsCommand
     *
     * @param args command line arguments
     */
    public CaListCAsCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
            
        if (args.length > 1) {
           String msg = "Lists the names of all available CAs.\nUsage: CA listcas";               
           throw new IllegalAdminCommandException(msg);
        }            
        try {
            ICAAdminSessionRemote casession = getCAAdminSessionRemote();
            Collection caids = casession.getAvailableCAs(administrator);
            Iterator iter = caids.iterator();
            while (iter.hasNext()) {
                int caid = ((Integer)iter.next()).intValue();
                CAInfo ca = casession.getCAInfo(administrator,caid);
                getOutputStream().println();
                getOutputStream().println("CA Name: "+ca.getName());
                getOutputStream().println("Id: "+ca.getCAId());
                getOutputStream().println("DN: "+ca.getSubjectDN());
                getOutputStream().println("Type: "+ca.getCAType());
                getOutputStream().println("Expire time: "+ca.getExpireTime());
                getOutputStream().println("Signed by: "+ca.getSignedBy());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
