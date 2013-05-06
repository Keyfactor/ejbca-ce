/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.cli.ca;

import java.util.List;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.util.CliTools;

/**
 * Changes fields in a CA.
 *
 * @version $Id$
 */
public class CaEditCaCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "editca"; }
    public String getDescription() { return "Edits CA fields of an existing CA."; }

    public void execute(String[] args) throws ErrorAdminCommandException {       
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <CA name> <field name> <field value>\n"+
                    "\n"+
            "Fields that can be set are derived from setFieldName of the CA java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName value'\n"+
            "Example: ca editca CAName CRLPeriod 2592000000\n"+
            "Example: ca editca CAName CRLIssueInterval 100000\n"+
            "Example: ca editca CAName includeInHealthCheck false\n"+
            "\n"+
            "Use the option -listFields to only list available fields in the CA. Note that there will always be some fields displayed which are not actually changeable.\n"+
            "Example: ca editca CAName -listFields\n"+
            "\n"+
            "Use the option -getValue to only get the value of a field in the CA.\n"+
            "Example: ca editca CAName -getValue CRLPeriod");
            return;
        }
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        FieldEditor fieldEditor = new FieldEditor(getLogger());
        try {
            CryptoProviderTools.installBCProvider();
            List<String> argsList = CliTools.getAsModifyableList(args);
            int index;
            boolean listOnly = false;
            if ((index = argsList.indexOf("-listFields")) != -1) {
                argsList.remove(index);
                // Only list fields available
                listOnly = true;
            }
            boolean getOnly = false;
            if ((index = argsList.indexOf("-getValue")) != -1) {
                argsList.remove(index);
                // Only get value of a field
                getOnly = true;
            }
            args = argsList.toArray(new String[argsList.size()]);
            
            final String name = args[1];
            final String field;
            if (args.length > 2) {
                field = args[2];
            } else {
                field= null;
            }
            final String value;
            if (args.length > 3) {
                value = args[3];
            } else {
                value = null;
            }

            final CAInfo cainfo = ejb.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), name);
            if (cainfo == null) {
                getLogger().info("CA '"+name+"' does not exist.");
            } else {
                // List fields, get values or set value
                if (!fieldEditor.listGetOrSet(listOnly, getOnly, name, field, value, cainfo)) {
                    getLogger().info("Storing modified CA info for CA '"+name+"'...");
                    ejb.getRemoteSession(CaSessionRemote.class).editCA(getAdmin(cliUserName, cliPassword), cainfo);
                    // Verify our new value
                    getLogger().info("Reading modified value for verification...");
                    final CAInfo cainfomod = ejb.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), name);
                    // Print return value
                    fieldEditor.getBeanValue(field, cainfomod);                    
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
