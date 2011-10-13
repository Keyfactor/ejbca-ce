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

import java.lang.reflect.Method;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes fields in a Publisher.
 *
 * @version $Id$
 */
public class CaEditPublisherCommand extends BaseCaAdminCommand {

    public String getMainCommand() { return MAINCOMMAND; }
    public String getSubCommand() { return "editpublisher"; }
    public String getDescription() { return "Edits publisher fields of an existing publisher in the CA."; }

    public void execute(String[] args) throws ErrorAdminCommandException {

        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <publisher name> <field name>=<field value>\n"+
                    "Only String value fields can be modified in this version.\n\n"+
            "Exemple: ca editpublisher PublisherName hostnames=myhost.com");
            return;
        }
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        try {
            CryptoProviderTools.installBCProvider();
            final String name = args[1];
            final String fieldEdit = args[2];
            final BasePublisher pub = ejb.getPublisherSession().getPublisher(name);
            if (pub == null) {
                getLogger().info("Publisher '"+name+"' does not exist.");
            } else {                
                final String[] fieldArray = StringUtils.split(fieldEdit, '=');
                if ((fieldArray == null) || (fieldArray.length == 0) || (fieldArray.length < 2)) {
                    getLogger().info("No fields found, enter field and modifyer like 'hostname=myhost.com'");
                    return;
                }
                final String field = fieldArray[0];
                final String fieldValue = fieldArray[1];
                char firstChar = field.charAt(0);
                final String setmethodName = "set"+String.valueOf(firstChar).toUpperCase()+field.substring(1);
                final String getMethodName = "get"+String.valueOf(firstChar).toUpperCase()+field.substring(1);
                getLogger().info("Modified publisher '"+name+"'...");
                getLogger().info("Trying to find method '"+getMethodName+"' in class "+pub.getClass());
                final Method modMethod;
                try {
                    modMethod = pub.getClass().getMethod(getMethodName);                    
                } catch (NoSuchMethodException e) {
                    throw new ErrorAdminCommandException("Method '"+getMethodName+"' does not exist. Did you use correct case for every character of the field?");
                }
                getLogger().info("Invoking method '"+getMethodName+"' vith no parameters.");
                Object o = modMethod.invoke(pub);
                getLogger().info("Old value for '"+field+"' is '"+o+"'.");
                getLogger().info("Trying to find method '"+setmethodName+"' in class "+pub.getClass());
                final Method method;
                try {
                    method = pub.getClass().getMethod(setmethodName, String.class);
                } catch (NoSuchMethodException e) {
                    throw new ErrorAdminCommandException("Method '"+setmethodName+"' with parameter of type java.lang.String does not exist. Did you use correct case for every character of the field?");
                }
                getLogger().info("Invoking method '"+setmethodName+"' vith parameter value '"+fieldValue+"'.");
                method.invoke(pub, fieldValue);
                getLogger().info("Storing modified publisher '"+name+"'...");
                ejb.getPublisherSession().changePublisher(getAdmin(cliUserName, cliPassword), name, pub);
                // Verify our new value
                getLogger().info("Reading modified value for verification...");
                final BasePublisher modpub = ejb.getPublisherSession().getPublisher(name);
                Object modo = modMethod.invoke(modpub);
                getLogger().info(getMethodName+" returned new value '"+modo+"'.");
                if (!modo.equals(fieldValue)) {
                    getLogger().error("Modified value '"+modo+"' is not the expected '"+fieldValue+"'.");                
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
