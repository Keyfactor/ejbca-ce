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

import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Remove a Publisher from the system. If there are references from CAs and/or certificate profiles, you can optionally also remove these, or just list them.
 * 
 * @version $Id$
 */
public class CaRemovePublisherCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaRemovePublisherCommand.class);
    
    private static final String PUBL_NAME_KEY = "--name";
    private static final String LIST_REF_KEY = "--listref";
    private static final String REMOVE_REF_KEY = "--removeref";
    private static final String REMOVE_ALL_KEY = "--removeall";
    

    {
        registerParameter(new Parameter(PUBL_NAME_KEY, "Publisher Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the Publisher. If no flags are provided, removing the publisher will work if there are no references to the publisher from CAs or Certificate Profiles."));
        registerParameter(Parameter.createFlag(LIST_REF_KEY, "Lists all references (you are authorized to) to the publisher, without removing the publisher."));
        registerParameter(Parameter.createFlag(REMOVE_REF_KEY, "Removes all references (you are authorized to) to the publisher, without removing the publisher."));
        registerParameter(Parameter.createFlag(REMOVE_ALL_KEY, "Removes all references (you are authorized to) to the publisher, and removes the publisher as well."));

         
    }

    @Override
    public String getMainCommand() {
        return "removepublisher";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String name = parameters.get(PUBL_NAME_KEY);
        boolean listrefmode = parameters.containsKey(LIST_REF_KEY);
        boolean removerefmode = parameters.containsKey(REMOVE_REF_KEY);
        boolean removeallmode = parameters.containsKey(REMOVE_ALL_KEY);
        try {
            final PublisherSessionRemote pubsession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
            final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
            final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
            // Get the publisher info
            final BasePublisher pub = pubsession.getPublisher(name);
            if (pub == null) {
                getLogger().info("Publisher with name '"+name+"' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // Find references in CAs and certificate profiles
            final int publisherId = pub.getPublisherId();
            // Only CAs this admin is authorized to
            List<Integer> caids = caSession.getAuthorizedCaIds(getAuthenticationToken());
            boolean caContains = false;
            for (Integer caid : caids) {
                try {
                    CAInfo cainfo = caSession.getCAInfo(getAuthenticationToken(), caid);
                    Collection<Integer> publisherIds = cainfo.getCRLPublishers();
                    if (publisherIds.contains(publisherId)) {
                        getLogger().info("CA '"+cainfo.getName()+"' contains a reference to the publisher '"+name+"'.");
                        if (removerefmode || removeallmode) {
                            publisherIds.remove(publisherId);
                            caSession.editCA(getAuthenticationToken(), cainfo);
                            getLogger().info("Removed publisher reference '"+name+"' from CA '"+cainfo.getName()+"'.");
                        } else {
                            caContains = true;
                        }
                    }
                } catch (CADoesntExistsException e) {
                    log.error("CA with id "+caid+"suddenly disappeared...ignoring.");
                }
            }
            final CertificateProfileSessionRemote cpSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
            Collection<Integer> cps = cpSession.getAuthorizedCertificateProfileIds(getAuthenticationToken(), 0);
            boolean cpContains = false;
            for (Integer cpid : cps) {
                CertificateProfile profile = cpSession.getCertificateProfile(cpid);
                Collection<Integer> publisherIds = profile.getPublisherList();
                if (publisherIds.contains(publisherId)) {
                    getLogger().info("Certificate profile '"+cpSession.getCertificateProfileName(cpid)+"' contains a reference to the publisher '"+name+"'.");
                    if (removerefmode || removeallmode) {
                        final String cpName = cpSession.getCertificateProfileName(cpid);
                        publisherIds.remove(publisherId);
                        cpSession.changeCertificateProfile(getAuthenticationToken(), cpName, profile);
                        getLogger().info("Removed publisher reference '"+name+"' from Certificate Profile '"+cpName+"'.");
                    } else {
                        cpContains = true;
                    }
                }
            }
            // Only remove publisher if we are not only listing or removing references
            if (!removerefmode && !listrefmode) {
                if (caContains || cpContains) {
                    log.error("Unable to remove publisher that still has references in CAs or Certificate Profiles.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                // Check that there are no references left
                if (caAdminSession.exitsPublisherInCAs(publisherId) || certificateProfileSession.existsPublisherIdInCertificateProfiles(publisherId)) {
                    log.error("Unable to remove publisher that still still has references in CAs or Certificate Profiles.");
                    return CommandResult.FUNCTIONAL_FAILURE;                    
                }
                pubsession.removePublisher(getAuthenticationToken(), name);
                getLogger().info("Removed publisher '"+name+"'.");
            }
        } catch (AuthorizationDeniedException e1) {
            log.error("CLI User was not authorized to remove publishers.");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (ReferencesToItemExistException e1) {
            log.error("The publisher is in use. " + e1.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Remove the Publisher from the system, optionally also removing references from CAs and Certificate Profiles.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()+"\nNote: Can only list/remove references in CAs and Certificate Profiles that you are authorized to.\n"+
                "Command can be used to list references, remove references, or remove both references and Publisher.\n"+
                "References are 'CRL Publishers' in CA configuration, and 'Publishers' in Certificate Profiles.";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }

}
