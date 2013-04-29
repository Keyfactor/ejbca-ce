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
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

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
                    "\n"+
            "Fields that can be set are derived from setFieldName of the publisher java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName=value'\n"+
            "Example: ca editpublisher PublisherName hostnames=myhost.com\n"+
            "Example: ca editpublisher PublisherName -paramType boolean AddMultipleCertificates=true\n"+
            "Example: ca editpublisher PublisherName -paramType int ConnectionTimeOut=10000\n"+
            "\n"+
            "Use the option -listFields to only list available fields in the publisher.\n"+
            "Example: ca editpublisher PublisherName -listFields\n"+
            "\n"+
            "Use the option -getValue to only get the value of a field in the publisher.\n"+
            "Example: ca editpublisher PublisherName -getValue hostnames");
            return;
        }
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        try {
            CryptoProviderTools.installBCProvider();
            List<String> argsList = CliTools.getAsModifyableList(args);
            // See if we have defined what type of parameter we should have to the method
            String paramType = "java.lang.String";
            int index;
            if ((index = argsList.indexOf("-paramType")) != -1) {
                paramType = argsList.get(index + 1);
                argsList.remove(index + 1);
                argsList.remove(index);
            }
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
            final String fieldEdit;
            if (args.length > 2) {
                fieldEdit = args[2];
            } else {
                fieldEdit = null;
            }
            final BasePublisher pub = ejb.getRemoteSession(PublisherSessionRemote.class).getPublisher(name);
            if (pub == null) {
                getLogger().info("Publisher '"+name+"' does not exist.");
            } else {                
                if (listOnly) {
                    listSetMethods(pub.getClass());
                    return;
                }
                if (getOnly) {
                    final String getMethodName = "get"+String.valueOf(fieldEdit.charAt(0)).toUpperCase()+fieldEdit.substring(1);
                    final Method modMethod = getGetterMethod(pub, getMethodName);
                    final Object gotValue = modMethod.invoke(pub);
                    getLogger().info(getMethodName+" returned value '"+gotValue+"'.");
                    return;
                }

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
                getLogger().info("Modifying publisher '"+name+"'...");
                
                Class<?> clazz = getClassFromType(paramType);
                Object value = getFieldValueAsObject(fieldValue, clazz);
                final Method modMethod = setFieldInBeanClass(pub, paramType, fieldValue, setmethodName, getMethodName, value);
                
                getLogger().info("Storing modified publisher '"+name+"'...");
                ejb.getRemoteSession(PublisherSessionRemote.class).changePublisher(getAdmin(cliUserName, cliPassword), name, pub);
                // Verify our new value
                getLogger().info("Reading modified value for verification...");
                final BasePublisher modpub = ejb.getRemoteSession(PublisherSessionRemote.class).getPublisher(name);
                Object modo = modMethod.invoke(modpub);
                getLogger().info(getMethodName+" returned new value '"+modo+"'.");
                if (!modo.equals(value)) {
                    getLogger().error("Modified value '"+modo+"' is not the expected '"+fieldValue+"'.");                
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
