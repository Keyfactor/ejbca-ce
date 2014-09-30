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

import java.io.IOException;

/**
 * @version $Id$
 *
 */
public interface CliCommand {

    /**
     * Executes whatever this command specifies
     * 
     * @param arguments an array of arguments parsed into this command.
     * @throws IOException for any IO related issues.
     */
    CommandResult execute(String... arguments);

    /**
     * @return a human friendly description of the implementing command.
     */
    String getCommandDescription();
}
