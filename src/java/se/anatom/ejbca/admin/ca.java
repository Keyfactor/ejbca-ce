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

import org.apache.log4j.PropertyConfigurator;


/**
 * Implements the CA command line interface
 *
 * @version $Id: ca.java,v 1.36 2004-04-16 07:38:57 anatom Exp $
 */
public class ca extends BaseCommand {
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        PropertyConfigurator.configure("log4j.properties");

        try {
            IAdminCommand cmd = CaAdminCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: CA info | init | listcas | makeroot | getrootcert | makereq | recrep | processreq | createcrl | getcrl | rolloverroot | rolloversub | listexpired | exportprofiles | importprofiles");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            //e.printStackTrace();
            System.exit(-1);
        }
    }
}


//ca
