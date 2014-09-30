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

import java.util.Set;

/**
 * A marker interface (mostly)
 * 
 * @version $Id$
 *
 */
public interface CliCommandPlugin extends CliCommand {
    
    /**
     * @return the main entrance path to the implementing command.
     */
    String getMainCommand();
    
    /**
     * 
     * @return a set of aliases to the command
     */
    Set<String> getMainCommandAliases();
    
    /**
     * 
     * @return a path of super commands leading to this command. Conflicts will be resolved at runtime.
     */
    String[] getCommandPath();
    
    /**
     * 
     * @return aliases for the super commands leading to this path. Conflicts will be resolved at runtime.
     */
    Set<String[]> getCommandPathAliases();
}
