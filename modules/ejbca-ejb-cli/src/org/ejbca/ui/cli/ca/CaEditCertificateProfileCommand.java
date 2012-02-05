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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Changes fields in a Certificate Profile.
 *
 * @version $Id$
 */
public class CaEditCertificateProfileCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "editcertificateprofile"; }
    public String getDescription() { return "Edits profile fields of an existing certificate profile in the CA."; }

    public void execute(String[] args) throws ErrorAdminCommandException {       
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <profile name> <field name>=<field value>\n"+
                    "Only String value fields can be modified in this version.\n\n"+
            "Fields that can be set are derived from setFieldName of the CertificateProfile java code. If there is a 'setFieldName(String)' method, the values to use in this command should be 'fieldName=value'\n"+
            "To set a parameter of type List<String>, add the -paramType=java.util.List\n"+
            "Example: ca editcertificateprofile CertProfileName CRLDistributionPointURI=http://my-crl-distp.com/my.crl\n"+
            "Example: ca editcertificateprofile CertProfileName -paramType java.util.List CaIssuers=http://my-ca.issuer.com/ca");
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
            int index;
            // See if we have defined what type of parameter we shoul dhave to the method
            String paramType = "java.lang.String";
            if ((index = argsList.indexOf("-paramType")) != -1) {
                paramType = argsList.get(index + 1);
                argsList.remove(index + 1);
                argsList.remove(index);
                args = argsList.toArray(new String[0]);
            }

            final String name = args[1];
            final String fieldEdit = args[2];
            final CertificateProfile profile = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(name);
            if (profile == null) {
                getLogger().info("Certificate profile '"+name+"' does not exist.");
            } else {
                final String[] fieldArray = StringUtils.split(fieldEdit, "=", 2);
                if ((fieldArray == null) || (fieldArray.length == 0) || (fieldArray.length < 2)) {
                    getLogger().info("No fields found, enter field and modifyer like 'CRLDistributionPointURI=http://my-crl-distp.com/my.crl'");
                    return;
                }
                final String field = fieldArray[0];
                final String fieldValue = fieldArray[1];
                char firstChar = field.charAt(0);
                final String setmethodName = "set"+String.valueOf(firstChar).toUpperCase()+field.substring(1);
                final String getMethodName = "get"+String.valueOf(firstChar).toUpperCase()+field.substring(1);
                getLogger().info("Modified publisher '"+name+"'...");
                getLogger().info("Trying to find method '"+getMethodName+"' in class "+profile.getClass());
                final Method modMethod;
                try {
                    modMethod = profile.getClass().getMethod(getMethodName);                    
                } catch (NoSuchMethodException e) {
                    throw new ErrorAdminCommandException("Method '"+getMethodName+"' does not exist. Did you use correct case for every character of the field?");
                }
                getLogger().info("Invoking method '"+getMethodName+"' vith no parameters.");
                Object o = modMethod.invoke(profile);
                getLogger().info("Old value for '"+field+"' is '"+o+"'.");
                getLogger().info("Trying to find method '"+setmethodName+"' in class "+profile.getClass());
                Class<?> clazz = Class.forName(paramType);
                final Method method;
                try {
                    method = profile.getClass().getMethod(setmethodName, clazz);
                } catch (NoSuchMethodException e) {
                    throw new ErrorAdminCommandException("Method '"+setmethodName+"' with parameter of type "+clazz.getName()+" does not exist. Did you use correct case for every character of the field?");
                }
                Object value = fieldValue;
                if (clazz.getName().equals(List.class.getName())) {
                    ArrayList<String> list = new ArrayList<String>();
                    list.add(fieldValue);
                    value = list;
                }
                getLogger().info("Invoking method '"+setmethodName+"' vith parameter value '"+fieldValue+"'.");
                method.invoke(profile, value);
                getLogger().info("Storing modified publisher '"+name+"'...");
                ejb.getRemoteSession(CertificateProfileSessionRemote.class).changeCertificateProfile(getAdmin(cliUserName, cliPassword), name, profile);
                // Verify our new value
                getLogger().info("Reading modified value for verification...");
                final CertificateProfile modprof = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(name);
                Object modo = modMethod.invoke(modprof);
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
