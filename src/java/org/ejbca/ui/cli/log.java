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
 * 
 * @version $Id$
 *
 */
public class log extends BaseCommand {

    public static void main(String[] args) {
        try {
            IAdminCommand cmd = LogAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: LOG " + LogAdminCommandFactory.getAvailableCommands());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            //e.printStackTrace();
            System.exit(-1);
        }
    } // main

}
