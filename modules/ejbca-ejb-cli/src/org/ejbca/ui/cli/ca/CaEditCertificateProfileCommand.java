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

import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.util.CliTools;

/**
 * Changes fields in a Certificate Profile.
 *
 * @version $Id$
 */
public class CaEditCertificateProfileCommand extends BaseCaAdminCommand {

    @Override
    public String getSubCommand() { return "editcertificateprofile"; }
    @Override
    public String getDescription() { return "Edits profile fields of an existing certificate profile in the CA."; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {       
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <profile name> <field name> <field value>\n"+
                    "\n"+
            "Fields that can be set are derived from setFieldName of the CertificateProfile java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName value'\n"+
            "Example: ca editcertificateprofile CertProfileName CRLDistributionPointURI http://my-crl-distp.com/my.crl\n"+
            "Example: ca editcertificateprofile CertProfileName caIssuers http://my-ca.issuer.com/ca\n"+
            "Example: ca editcertificateprofile CertProfileName useOcspNoCheck true\n"+
            "Example: ca editcertificateprofile CertProfileName numOfReqApprovals 1\n"+
            "\n"+
            "Use the option -listFields to only list available fields in the certificate profile.\n"+
            "Example: ca editcertificateprofile CertProfileName -listFields\n"+
            "\n"+
            "Use the option -getValue to only get the value of a field in the certificate profile.\n"+
            "Example: ca editcertificateprofile CertProfileName -getValue caIssuers");
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

            final CertificateProfile profile = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(name);
            if (profile == null) {
                getLogger().info("Certificate profile '"+name+"' does not exist.");
            } else {
                // List fields, get values or set value
                if (!fieldEditor.listGetOrSet(listOnly, getOnly, name, field, value, profile)) {
                    
                    getLogger().info("Storing modified profile '"+name+"'...");
                    ejb.getRemoteSession(CertificateProfileSessionRemote.class).changeCertificateProfile(getAuthenticationToken(cliUserName, cliPassword), name, profile);
                    // Verify our new value
                    getLogger().info("Reading modified value for verification...");
                    final CertificateProfile modprof = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(name);

                    // Print return value
                    fieldEditor.getBeanValue(field, modprof);                    
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
