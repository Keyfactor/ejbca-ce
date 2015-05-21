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

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Removes an administrator from an Administrator role
 *
 * @version $Id: CaCertRequestCommand.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class RemoveSubjectFromRoleCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


    private static final int ARG_ROLE_NAME    = 1;
    private static final int ARG_CA_NAME      = 2;
    private static final int ARG_MATCH_WITH   = 3;
    private static final int ARG_MATCH_TYPE   = 4;
    private static final int ARG_MATCH_VALUE  = 5;

    /**
     * Creates a new instance of Command
     *
     * @param args command line arguments
     */
    public RemoveSubjectFromRoleCommand(String[] args) {
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
            if (args.length < 6 ) {
                getPrintStream().println("Error. Too few arguments: "+args.length);
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }

            String rolename = args[ARG_ROLE_NAME];
            String caname = args[ARG_CA_NAME];
            String matchwith = args[ARG_MATCH_WITH];
            String matchtype = args[ARG_MATCH_TYPE];
            String matchvalue = args[ARG_MATCH_VALUE];
            
            getEjbcaRAWS().removeSubjectFromRole(rolename, caname, matchwith, matchtype, matchvalue);
            getPrintStream().println("Added admin to " + rolename + " successfully");
        } catch (Exception e) {
            if (e instanceof EjbcaException_Exception) {
                EjbcaException_Exception e1 = (EjbcaException_Exception)e;
                getPrintStream().println("Error code: " + e1.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
            ErrorAdminCommandException adminexp = new ErrorAdminCommandException(e);
            getPrintStream().println("Error message: " + adminexp.getLocalizedMessage());
        }
    }

    protected void usage() {
        
        getPrintStream().println("Command used to remove an administrator from a role");
        getPrintStream().println("Usage : removeadminfromrole <rolename> <caname> <matchwith> <matchtype> <matchvalue>");
        getPrintStream().println();
        
        String availableMatchers = "";
        for (AccessMatchValue currentMatchWith : X500PrincipalAccessMatchValue.values()) {
            availableMatchers += (availableMatchers.length() == 0 ? "" : ", ") + currentMatchWith;
        }
        getPrintStream().println("Matchwith can be: " + availableMatchers);
        getPrintStream().println();
        String availableMatchTypes = "";
        for (AccessMatchType currentMatchType : AccessMatchType.values()) {
            availableMatchTypes += (availableMatchTypes.length() == 0 ? "" : ", ") + currentMatchType;
        }
        getPrintStream().println("Matchtype can be: " + availableMatchTypes);
    }
}
