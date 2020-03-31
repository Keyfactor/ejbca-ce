package org.ejbca.core.protocol.ws.client;

import org.ejbca.config.InternalConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Ability to get version of clientToolBox
 * ./ejbcaClientToolBox.sh EjbcaWsRaCli getClientToolBoxVersion
 *
 * @version $Id$
 */
public class GetClientToolBoxVersionCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    GetClientToolBoxVersionCommand(String[] args) {
        super(args);
    }

    @Override
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        String ejbcaVersion;
        String toolBoxVersion;
        toolBoxVersion = InternalConfiguration.getAppVersion();
        try {
            ejbcaVersion = getEjbcaRAWS().getEjbcaVersion();
            System.out.println("ClientToolBoxVersion: " + toolBoxVersion);
            System.out.println("EJBCA version: " + ejbcaVersion);
        } catch (Exception e) {
            ErrorAdminCommandException adminexp = new ErrorAdminCommandException(e);
            getPrintStream().println("Error: " + adminexp.getLocalizedMessage());
        }
    }

    @Override
    protected void usage() {

    }

}

