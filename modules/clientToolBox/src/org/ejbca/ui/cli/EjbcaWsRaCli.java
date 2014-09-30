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

import java.util.ArrayList;
import java.util.List;

/**
 * Implements the EJBCA RA WS command line interface
 *
 * @version $Id$
 */
public class EjbcaWsRaCli extends ClientToolBox {
    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        final List<String> lArgs = new ArrayList<String>();
        for ( int i=1; i<args.length; i++)  { // remove first argument
            lArgs.add(args[i]);
        }
        try {
        	// the ejbcawsracli can not be compiled when building EJBCA.
            Class.forName("org.ejbca.core.protocol.ws.client.ejbcawsracli").getMethod("main", new Class<?>[]{String[].class}).invoke(null, new Object[]{lArgs.toArray(new String[]{})});
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "EjbcaWsRaCli";
    }
}
