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

import javax.security.auth.login.FailedLoginException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Activates the specified HSM CA.
 * 
 * @version $Id: CaActivateCACommand.java 9345 2010-07-01 15:51:20Z mikekushner$
 */
public class CaActivateCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaActivateCACommand.class);
    
    private static final String CA_NAME_KEY = "--caname";
    private static final String AUTHORIZATION_CODE_KEY = "--code";
    
    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "CA Name"));
        registerParameter(new Parameter(AUTHORIZATION_CODE_KEY, "Authorization Code", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Leaving out authorization code will prompt for it."));
    }
     
    @Override
    public String getMainCommand() {
        return "activateca";
    }

    @Override
    public String getCommandDescription() {
        return "Activates the specified HSM CA";
    }

    @Override
    public String getFullHelpText() {
        return "Activates the specified HSM CA. Leaving out authorization code will prompt for it.";
    }
    
    @Override
    public CommandResult execute(ParameterContainer parameters) {
        try {
            String caname = parameters.get(CA_NAME_KEY);
            String authorizationcode = parameters.get(AUTHORIZATION_CODE_KEY);
            if(authorizationcode == null) {
                log.info("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on the
                // console
                authorizationcode = String.valueOf(System.console().readPassword());
            }
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo;
            try {
                cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
            } catch (CADoesntExistsException e1) {
                log.error("Error: CA " + caname + " cannot be found");
                return CommandResult.FUNCTIONAL_FAILURE;
            } 
            if (cainfo == null) {
                log.error("Error: CA " + caname + " cannot be found");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // Check that CA has correct status.
            final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final boolean tokenOffline = !cryptoTokenManagementSession.isCryptoTokenStatusActive(getAuthenticationToken(), cryptoTokenId);
            if (cainfo.getStatus()==CAConstants.CA_OFFLINE || tokenOffline) {
                try {
                    if (cainfo.getStatus() == CAConstants.CA_OFFLINE) {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).activateCAService(getAuthenticationToken(), cainfo.getCAId());
                        log.info("CA Service activated.");
                    }
                    if (tokenOffline) {
                        cryptoTokenManagementSession.activate(getAuthenticationToken(), cryptoTokenId, authorizationcode.toCharArray());
                        log.info("CA's CryptoToken activated.");
                    }
                    return CommandResult.SUCCESS;
                } catch (CryptoTokenAuthenticationFailedException e) {
                    log.error("CA Token authentication failed.");
                    log.error(e.getMessage());
                    Throwable t = e.getCause();
                    while (t != null) {
                        if (t instanceof FailedLoginException) {
                            // If it's an HSM the next exception will be a PKCS11 exception. We don't want to search directly for that though, 
                            // because then we will import sun specific classes, and we don't want that.
                            t = t.getCause();
                            if (t != null) {
                                log.error(t.getMessage());
                                break;
                            }
                        } else {
                            t = t.getCause();
                        }
                    }
                    log.debug("Exception: ", e);
                } catch (ApprovalException e) {
                    log.error("CA Token activation approval request already exists.");
                } catch (WaitingForApprovalException e) {
                    log.error("CA requires an approval to be activated. A request have been sent to authorized admins.");
                } catch(CryptoTokenOfflineException e) {
                    log.error("Cryptotoken with ID " + cryptoTokenId + " was not available." , e);
                }
            } else {
                log.error("CA or CAToken must be offline to be activated.");
            }
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user was not authorized to perform this operation", e);
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch(CADoesntExistsException e) {
            //Ignore, can not happen since we have already checked for CA existence.
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
