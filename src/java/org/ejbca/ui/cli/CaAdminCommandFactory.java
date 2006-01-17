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
 * Factory for CA Admin Commands.
 *
 * @version $Id: CaAdminCommandFactory.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class CaAdminCommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private CaAdminCommandFactory() {
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

        if (args[0].equals("getrootcert")) {
            return new CaGetRootCertCommand(args);
        } else if (args[0].equals("listexpired")) {
            return new CaListExpiredCommand(args);
        } else if (args[0].equals("info")) {
            return new CaInfoCommand(args);
        } else if (args[0].equals("listcas")) {
            return new CaListCAsCommand(args);
        } else if (args[0].equals("init")) {
            return new CaInitCommand(args);
        } else if (args[0].equals("createcrl")) {
            return new CaCreateCrlCommand(args);
        } else if (args[0].equals("getcrl")) {
            return new CaGetCrlCommand(args);
        } else if (args[0].equals("exportprofiles")) {
            return new CaExportProfilesCommand(args);
        } else if (args[0].equals("importprofiles")) {
            return new CaImportProfilesCommand(args);
        } else if (args[0].equals("importca")) {
            return new CaImportCACommand(args);
        } else if (args[0].equals("importcert")) {
            return new CaImportCertCommand(args);
        } else if (args[0].equals("republish")) {
            return new CARepublishCommand(args);
        } else {
            return null;
        }
    }

    // getCommand
}


// CaAdminCommandFactory
