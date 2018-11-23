/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import org.ejbca.ui.cli.dbmanager.DBManager;
import org.ejbca.ui.cli.jdbc.JdbcTool;

/**
 * Extend this class for each new tool you want to add and add the new extended class to the toolBox array in {@link #main(String[])}
 * @version $Id$
 */
public abstract class ClientToolBox {

    /**
     * Execute the command issued from the command line.
     * @param args from command line
     */
    protected abstract void execute(String[] args);
    /**
     * @return the name of the tool.
     */
    protected abstract String getName();
    /**
     * Check if this tool should be executed.
     * @param args Command line from the user.
     */
    boolean executeIfSelected(String args[]) {
        if (args[0].equalsIgnoreCase(getName())) {
            execute(args);
            return true;
        }
        return false;
    }
    /**
     *
     * @param args The arguments issued by the user. First argument selects the tool to use.
     */
    public static void main(String[] args) {
        // each new tool must be added to the array
        final ClientToolBox toolBox[] = {
        		new HealthCheckTest(),
        		new HSMKeyTool(),
        		new Ocsp(),
        		new EjbcaWsRaCli(),
        		new CvcWsRaCli(),
        		new CMPTest(),
        		new CMPKeyUpdateStressTest(),
        		new SCEPTest(),
                new OCSPActivate(),
                new DBManager(),
                new PasswordGenerator(),
                new CaIdGenerator(),
                new JdbcTool(),
        };
        for ( int i=0; args.length>0 && i<toolBox.length; i++) {
            if ( toolBox[i].executeIfSelected(args) ) {
                return;
            }
        }
        System.err.println("You must specify which tool to use as first argument.");
        System.err.println("These tools are available:");
        for ( int i=0; i<toolBox.length; i++) {
            System.err.println(" - "+toolBox[i].getName());
        }
    }

}
