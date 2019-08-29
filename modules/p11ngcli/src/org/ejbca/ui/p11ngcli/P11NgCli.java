/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli;

import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.library.CommandLibrary;

/**
 * Entry class for the P11NgCli command
 * 
 * $Id$
 */
public class P11NgCli {

    public static void main(String[] args) {
        if (args.length == 0 || !CommandLibrary.INSTANCE.doesCommandExist(args)) {
            CommandLibrary.INSTANCE.listRootCommands();
        } else {
            CryptoProviderTools.installBCProvider();
            CommandResult result = CommandLibrary.INSTANCE.findAndExecuteCommandFromParameters(args);
            if (result != CommandResult.SUCCESS) {
                System.exit(result.getReturnCode());
            }
        }
    }

}