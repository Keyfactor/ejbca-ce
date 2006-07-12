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
 * Implements the RA command line interface
 *
 * @version $Id: ra.java,v 1.3 2006-07-12 16:10:15 anatom Exp $
 */
public class ra extends BaseCommand {
    /**
     * main RA
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = RaAdminCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser | unrevokeuser | keyrecover | keyrecovernewest | setsubjectdirattr");            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
            System.exit(-1);
        }
    }
}
