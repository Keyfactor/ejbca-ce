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
 * Factory for General Setup Commands.
 *
 * @version $Id: SetupCommandFactory.java,v 1.3 2006-03-19 09:44:36 anatom Exp $
 */
public class SetupCommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private SetupCommandFactory() {
    }

    /**
     * Returns an Admin Command object based on contents in args[0].
     *
     * @param args array of arguments typically passed from main().
     *
     * @return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1) {
            return null;
        }

        if (args[0].equals("setdefaultbaseurl")) {
            return new SetupSetBaseURLCommand(args);
        }
        if (args[0].equals("initializehardtokenissuing")) {
        	return new InitializeHardTokenIssuing(args);
        }
        return null;
    } // getCommand
} // CaAdminCommandFactory
