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
package org.ejbca.ui.cli.infrastructure.command;

import com.keyfactor.util.string.StringConfigurationCache;

import org.cesecore.config.ConfigurationHolder;

/**
 * Base class for EJBCA commands that use the CLI user. 
 * 
 * @version $Id$
 *
 */
public abstract class EjbcaCliUserCommandBase extends PasswordUsingCommandBase {

    static {
        StringConfigurationCache.INSTANCE.setEncryptionKey(ConfigurationHolder.getString("password.encryption.key").toCharArray());
    }

    @Override
    public String getImplementationName() {
        return "EJBCA CLI";
    }
}
