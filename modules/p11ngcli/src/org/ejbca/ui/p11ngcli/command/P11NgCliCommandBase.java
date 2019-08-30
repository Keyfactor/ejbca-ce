/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli.command;

import java.nio.charset.StandardCharsets;

import org.ejbca.ui.cli.infrastructure.command.CommandBase;

/**
 * 
 * $Id$ 
 *
 */
public abstract class P11NgCliCommandBase extends CommandBase {

    public static final String UTF_8 = StandardCharsets.UTF_8.name(); //charset's canonical name e.g "UTF-8".

    @Override
    public String getImplementationName() {
        return "P11NG CLI";
    }
}