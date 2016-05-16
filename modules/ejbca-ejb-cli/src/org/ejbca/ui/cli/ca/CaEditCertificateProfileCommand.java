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

package org.ejbca.ui.cli.ca;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.FieldNotFoundException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes fields in a Certificate Profile.
 *
 * @version $Id$
 */
public class CaEditCertificateProfileCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaEditCertificateProfileCommand.class);

    private static final String CERTIFICATEPROFILE_NAME_KEY = "--cpname";
    private static final String FIELD_KEY = "--field";
    private static final String VALUE_KEY = "--value";
    private static final String LISTFIELDS_KEY = "-listFields";
    private static final String GETVALUE_KEY = "-getValue";

    {
        registerParameter(new Parameter(CERTIFICATEPROFILE_NAME_KEY, "Certificate Profile Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Name of the certificate profile."));
        registerParameter(new Parameter(FIELD_KEY, "Field Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The sought field."));
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The value to set, if any."));
        registerParameter(new Parameter(LISTFIELDS_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Set to only list available fields in the CA"));
        registerParameter(new Parameter(GETVALUE_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Use this to get the value of a single field"));
    }

    @Override
    public String getMainCommand() {
        return "editcertificateprofile";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        FieldEditor fieldEditor = new FieldEditor(log);

        CryptoProviderTools.installBCProvider();

        boolean listOnly = parameters.get(LISTFIELDS_KEY) != null;
        boolean getOnly = parameters.get(GETVALUE_KEY) != null;
        final String name = parameters.get(CERTIFICATEPROFILE_NAME_KEY);
        final String field = parameters.get(FIELD_KEY);
        final String value = parameters.get(VALUE_KEY);

        if(!listOnly && field == null) {
            log.error("No field was specified.");
            return CommandResult.CLI_FAILURE;
        } else if(!listOnly && !getOnly && value == null) {
            log.error("No value was specified.");
            return CommandResult.CLI_FAILURE;
        } else if(listOnly && getOnly) {
            log.error("Cannot specify both " + LISTFIELDS_KEY + " and " + GETVALUE_KEY);
            return CommandResult.CLI_FAILURE;
        } else if(getOnly && value != null) {
            log.error("Cannot submit a value with "+ GETVALUE_KEY + " set.");
            return CommandResult.CLI_FAILURE;
        }
        
        final CertificateProfile profile = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfile(
                name);
        if (profile == null) {
            log.info("Certificate profile '" + name + "' does not exist.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } else {
            // List fields, get values or set value
            try {
                if(listOnly) {
                    fieldEditor.listSetMethods(profile);
                } else if(getOnly) {
                    fieldEditor.getBeanValue(field, profile);
                }
                else {
                    fieldEditor.setValue(name, field, value, profile);             
                    log.info("Storing modified profile '" + name + "'...");
                    EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).changeCertificateProfile(
                            getAuthenticationToken(), name, profile);
                    // Verify our new value
                    log.info("Reading modified value for verification...");
                    final CertificateProfile modprof = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                            .getCertificateProfile(name);
                    // Print return value
                    fieldEditor.getBeanValue(field, modprof);
                }
                return CommandResult.SUCCESS;
            } catch (FieldNotFoundException e) {
                log.error(e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (AuthorizationDeniedException e) {
                log.error("CLI User was not authorized to Certificate Profile " + name);
                return CommandResult.AUTHORIZATION_FAILURE;
            }
        }

    }

    @Override
    public String getCommandDescription() {
        return "Edits profile fields of an existing certificate profile in the CA. ";
               
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "Fields that can be set are derived from setFieldName of the CertificateProfile java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName value'\n"
                + "Example: ca editcertificateprofile CertProfileName CRLDistributionPointURI http://my-crl-distp.com/my.crl\n"
                + "Example: ca editcertificateprofile CertProfileName caIssuers http://my-ca.issuer.com/ca\n"
                + "Example: ca editcertificateprofile CertProfileName useOcspNoCheck true\n"
                + "Example: ca editcertificateprofile CertProfileName numOfReqApprovals 1\n" + "\n"
                + "Use the option -listFields to only list available fields in the certificate profile.\n"
                + "Example: ca editcertificateprofile CertProfileName -listFields\n" + "\n"
                + "Use the option -getValue to only get the value of a field in the certificate profile.\n"
                + "Example: ca editcertificateprofile CertProfileName -getValue caIssuers";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
