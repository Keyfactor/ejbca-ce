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
                    "\n"+
            "Fields that can be set are derived from setFieldName of the CertificateProfile java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName=value'\n"+
            "To set a parameter of type List<String>, add the -paramType=java.util.List\n"+
            "Example: ca editcertificateprofile CertProfileName CRLDistributionPointURI=http://my-crl-distp.com/my.crl\n"+
            "Example: ca editcertificateprofile CertProfileName -paramType java.util.List CaIssuers=http://my-ca.issuer.com/ca\n"+
            "Example: ca editcertificateprofile CertProfileLdap -paramType boolean UseOcspNoCheck=true\n"+
            "Example: ca editcertificateprofile CertProfileLdap -paramType int NumOfReqApprovals=1\n"+
            "\n"+
            "Use the option -listFields to only list available fields in the certificate profile.\n"+
            "Example: ca editcertificateprofile CertProfileName -listFields\n"+
            "\n"+
            "Use the option -getValue to only get the value of a field in the certificate profile.\n"+
            "Example: ca editcertificateprofile CertProfileName -getValue CaIssuers");
            
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
            // See if we have defined what type of parameter we should have to the method
            String paramType = "java.lang.String";
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
            final CertificateProfile profile = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(name);
            if (profile == null) {
                getLogger().info("Certificate profile '"+name+"' does not exist.");
            } else {
                if (listOnly) {
                    listSetMethods(profile.getClass());
                    return;
                }
                if (getOnly) {
                    final String getMethodName = "get"+String.valueOf(fieldEdit.charAt(0)).toUpperCase()+fieldEdit.substring(1);
                    final Method modMethod = getGetterMethod(profile, getMethodName);
                    final Object gotValue = modMethod.invoke(profile);
                    getLogger().info(getMethodName+" returned value '"+gotValue+"'.");
                    return;
                }
                
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
                getLogger().info("Modifying certificate profile '"+name+"'...");

                Class<?> clazz = getClassFromType(paramType);
                Object value = getFieldValueAsObject(fieldValue, clazz);
                final Method modMethod = setFieldInBeanClass(profile, paramType, fieldValue, setmethodName, getMethodName, value);
                
                getLogger().info("Storing modified profile '"+name+"'...");
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
