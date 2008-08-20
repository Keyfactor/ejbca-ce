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
 * @author lars
 * @version $Id$
 *
 */
public abstract class ClientToolBox {

    /**
     * @param args
     */
    abstract void execute(String[] args);
    /**
     * @return
     */
    abstract String getName();
    /**
     * @param args
     */
    void executeIfSelected(String args[]) {
        if (args[0].equalsIgnoreCase(getName()))
            execute(args);
    }
    /**
     * @param args
     */
    public static void main(String[] args) {
        final ClientToolBox toolBox[] = { new HealthCheckTest(), new HSMKeyTool(), new PKCS11HSMKeyTool(), new NCipherHSMKeyTool() };
        if ( args.length<1 ) {
            System.err.println("You must specify which tool to use as first argument.");
            System.err.println("These tools are awailable:");
            for ( int i=0; i<toolBox.length; i++)
                System.err.println(" - "+toolBox[i].getName());
            return;
        }
        for ( int i=0; i<toolBox.length; i++)
            toolBox[i].executeIfSelected(args);
    }

}
