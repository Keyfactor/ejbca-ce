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


/**
 * Implements the setup command line interface
 *
 * @version $Id: setup.java,v 1.3 2004-06-28 12:03:52 sbailliez Exp $
 */
public class setup {
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = SetupCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: SETUP setbaseurl");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            //e.printStackTrace();
            System.exit(-1);
        }
    }
}


//ca
