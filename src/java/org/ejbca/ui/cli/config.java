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

/**
 * Implements the setup command line interface
 *
 * @version $Id: $
 */
public class config {

	/**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = ConfigCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println("Usage: CONFIG dump");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            System.exit(-1);
        }
    }

}
