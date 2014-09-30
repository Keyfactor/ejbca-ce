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
 
package org.ejbca.core.protocol.ws.client;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Displays the length of a publisher queue.
 *
 * @version $Id$
 */
public class GetPublisherQueueLength extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_PUBLISHER_NAME           = 1;
	
	
    /**
     * Creates a new instance of RevokeCertCommand
     *
     * @param args command line arguments
     */
    public GetPublisherQueueLength(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

    	try {   
           
            if(this.args.length < 2){
            	usage();
            	System.exit(-1); // NOPMD, this is not a JEE app
            }
            final String name = this.args[ARG_PUBLISHER_NAME];
            final int length = getEjbcaRAWS().getPublisherQueueLength(name);
            if ( length < 0 ) {
                getPrintStream().println("Publisher '"+name+"' does not exist.");
            } else {
                getPrintStream().println("The length of the queue for the publisher '"+name+"' is "+length+" items.");
            }
            System.exit(length); // return the length so that scripts may use it. // NOPMD, this is not a JEE app
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

	@Override
    protected void usage() {
		getPrintStream().println("The length of a publisher queue.");
		getPrintStream().println("Usage : getpublisherqueuelength <publisher name>");
		getPrintStream().println();
   }


}
