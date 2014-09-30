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

package org.ejbca.ui.cli;

import org.apache.log4j.Logger;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Clears caches used internally by EJBCA. The caches are used to limit the number of database queries issued to the database.
 * See conf/cache.properties.sample for configuration of caches.
 *
 * @version $Id$
 */
public class ClearCacheCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(ClearCacheCommand.class);
    private static final String ALL = "-all";
    private static final String GLOBAL_CONFIGURATION = "-globalconf";
    private static final String EE_PROFILES = "-eeprofile";
    private static final String CERTIFICATE_PROFILE = "-certprofile";
    private static final String AUTHORIZATION = "-authorization";
    private static final String CA_CACHE = "-ca";

    //Register parameters 
    {
        registerParameter(new Parameter(ALL, "All", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG, "Clear all caches."));
        registerParameter(new Parameter(GLOBAL_CONFIGURATION, "Global Configuration", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Clear global configuration cache."));
        registerParameter(new Parameter(EE_PROFILES, "End Entity Profiles", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Clear End Entity Profile Cache"));
        registerParameter(new Parameter(CERTIFICATE_PROFILE, "Certificate Profiles", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Clear Certificate Profile cache."));
        registerParameter(new Parameter(AUTHORIZATION, "Authorization", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Clear Authorization cache."));
        registerParameter(new Parameter(CA_CACHE, "CA Cache", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG, "Clear CA cache."));
    }

    @Override
    public String getMainCommand() {
        return "clearcache";
    }

    @Override
    public String getCommandDescription() {
        return "Clears caches used internally by EJBCA.";
    }

    @Override
    public String getFullHelpText() {
        return "Clears caches used internally by EJBCA. See conf/cache.properties.sample for config options. "
                + "This command should only be needed if cache times are set to very high values. "
                + "All arguments are optional, but you have to provide at least one.";
    }

    public CommandResult execute(ParameterContainer parameters) {
        // Get and remove switches
        final boolean all = parameters.get(ALL) != null;
        final boolean globalconf = (parameters.get(GLOBAL_CONFIGURATION) != null) || all;
        final boolean eeprofile = (parameters.get(EE_PROFILES) != null) || all;
        final boolean certprofile = (parameters.get(CERTIFICATE_PROFILE) != null) || all;
        final boolean authorization = (parameters.get(AUTHORIZATION) != null) || all;
        final boolean cacache = (parameters.get(CA_CACHE) != null) || all;

        if (!(all || globalconf || eeprofile || certprofile || authorization || cacache)) {
            log.error("ERROR: No caches were flushed because no parameters were specified.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        if (globalconf) {
            GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(GlobalConfigurationSessionRemote.class);
            log.info("Flushing Global Configuration cache.");
            // Flush GlobalConfiguration
            globalConfigurationSession.flushConfigurationCache(Configuration.GlobalConfigID);

            log.info("Flushing CMP configuration cache.");
            // Flush CMPConfiguration
            globalConfigurationSession.flushConfigurationCache(Configuration.CMPConfigID);
            
            log.info("Flushing SCEP configuration cache.");
            // Flush SCEP Configuration
            globalConfigurationSession.flushConfigurationCache(Configuration.ScepConfigID);
        }
        if (eeprofile) {
            log.info("Flushing End Entity Profile cache.");
            // Flush End Entity profiles
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).flushProfileCache();
        }
        if (certprofile) {
            log.info("Flushing Certificate Profile cache.");
            // Flush Certificate profiles
            EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).flushProfileCache();
        }
        if (authorization) {
            log.info("Flushing Authorization cache.");
            // Flush access control
            EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class).forceCacheExpire();
        }
        if (cacache) {
            log.info("Flushing CA cache.");
            // Flush CAs
            EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        }
        return CommandResult.SUCCESS;

    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
