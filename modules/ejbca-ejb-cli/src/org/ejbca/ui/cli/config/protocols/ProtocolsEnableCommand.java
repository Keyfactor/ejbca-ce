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
package org.ejbca.ui.cli.config.protocols;

/**
 * CLI command to enable an EJBCA protocol.
 * 
 * @version $Id$
 */
public class ProtocolsEnableCommand extends BaseProtocolsUpdateCommand {

    @Override
    public String getMainCommand() {
        return "enable";
    }

    @Override
    public String getCommandDescription() {
        return "Enable protocol.";
    }

    @Override
    protected boolean getNewStatus() {
        return true;
    }
}
