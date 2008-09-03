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
 * Implements the admins command line interface
 *
 * @version $Id: ca.java 5631 2008-05-22 11:46:54Z anatom $
 */
public class admins extends BaseCommand {
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = AdminsAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: admins " +
                    AdminsListGroupsCommand.COMMAND + " | " + AdminsAddGroupCommand.COMMAND + " | " + AdminsRemoveGroupCommand.COMMAND + " | " +
                    AdminsListAdminsCommand.COMMAND +" | " + AdminsAddAdminCommand.COMMAND +" | " + AdminsRemoveAdminCommand.COMMAND + " | " +
                    AdminsListRulesCommand.COMMAND +" | " + AdminsChangeRuleCommand.COMMAND);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());            
            System.exit(-1);
        }
    }
}
