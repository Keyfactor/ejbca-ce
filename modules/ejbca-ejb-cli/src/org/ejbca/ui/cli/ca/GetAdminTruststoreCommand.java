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

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CertTools;

public class GetAdminTruststoreCommand extends BaseCaAdminCommand {
    private static final Logger log = Logger.getLogger(GetAdminTruststoreCommand.class);

    private static final String FORMAT_KEY = "--format";
    private static final String TRUSTSTORE_KEY = "--truststore";
    private static final String PASSWORD_KEY = "--password";
    
    {
        registerParameter(new Parameter(FORMAT_KEY, "Format", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Truststore format [PEM (default), JKS, PKCS12]."));
        registerParameter(new Parameter(PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Truststore password.  Defaults to 'changeit'"));
        registerParameter(new Parameter(TRUSTSTORE_KEY, "Truststore", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to where the truststore file is written."));
    }
    
    @Override
    public String getMainCommand() {
        return "createtruststore";
    }

    @Override
    public String getCommandDescription() {
        return "Create a truststore from all CA's used in role matching.";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    protected CommandResult execute(final ParameterContainer parameters) {
        String format = parameters.get(FORMAT_KEY);
        if (format == null) {
            format = "PEM";
        }
        String password = parameters.get(PASSWORD_KEY);
        if (password == null) {
            password = "changeit";
        }
        final String truststore = parameters.get(TRUSTSTORE_KEY);
        
        final Set<X509Certificate> certs = new LinkedHashSet<>();
        
        final List<Role> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getAuthorizedRoles(getAuthenticationToken());
        final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
        for (final Role role : roles) {
            try {
                final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAuthenticationToken(), role.getRoleId());
                for (final RoleMember member : roleMembers) {
                    final int tokenIssuerId = member.getTokenIssuerId();
                    if (tokenIssuerId != RoleMember.NO_ISSUER) {
                        final CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                                member.getTokenIssuerId());
                        info.getCertificateChain().forEach(c -> {
                            if (c instanceof X509Certificate) {
                                certs.add((X509Certificate) c);
                            }
                        });
                    }
                }
            } catch (final AuthorizationDeniedException e) {
                getLogger().info("Unable to access certificate for role:" + role.getRoleName());
            }
        }
        
        if (format.equals("PEM")) {
            try (FileOutputStream truststoreStream = new FileOutputStream(truststore)) {
                for (final X509Certificate certificate : certs) {
                    truststoreStream.write(CertTools.getPemFromCertificateChain(Collections.singleton(certificate)));
                }
                getLogger().info(truststore + " created.");
            } catch (IOException | CertificateEncodingException e) {
                getLogger().error("Unable to write to " + truststore, e);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } else {
            try {
                final KeyStore keystore = KeyStore.getInstance(format);
                keystore.load(null, password.toCharArray());
                for (final X509Certificate certificate : certs) {
                    keystore.setCertificateEntry(CertTools.getSHA256FingerprintAsString(certificate.getEncoded()), certificate);
                }
                try (FileOutputStream truststoreStream = new FileOutputStream(truststore)) {
                    keystore.store(truststoreStream, password.toCharArray());
                }
                getLogger().info(truststore + " created.");
            } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
                getLogger().error("Unable to write to " + truststore, e);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }

        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        return "Create a truststore, in PKCS12, JKS or concatentated PEM format, containing \n"
                + "all the certificates used to match roles.\n";
    }

}
