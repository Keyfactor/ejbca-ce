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
 * Classes that implement this interface automatically becomes available to the EJBCA EJB CLI if
 * they are available in the class path.
 * 
 * @version $Id$
 * 
 */
public interface CliCommandPlugin {

    /**
     * Return the main/first argument used to invoke this command.
     */
    String getMainCommand();

    /**
     * Return the sub/second argument used to invoke this command.
     */
    String getSubCommand();

    /**
     * Return a description for this command.
     */
    String getDescription();

    /**
     * 
     * @return an array of deprecated/unused/aliased commands to the main command. 
     */
    String[] getMainCommandAliases();

    /**
     * 
     * @return an array of aliases for the various subcommands
     */
    String[] getSubCommandAliases();
    
    /**
     * Run the command.
     * @param args
     * @throws IllegalAdminCommandException
     * @throws ErrorAdminCommandException
     */
    void execute(String[] args) throws ErrorAdminCommandException;
}
