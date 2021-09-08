package org.ejbca.ui.cli.roles;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class GetAdminTruststoreCommand extends BaseRolesCommand {
    private static final Logger log = Logger.getLogger(GetAdminTruststoreCommand.class);

    private static final String FORMAT_KEY = "--format";
    private static final String TRUSTSTORE_KEY = "--truststore";
    
    {
        registerParameter(new Parameter(FORMAT_KEY, "Format", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Truststore format [PEM (default), JKS, PKCS12]."));
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
    protected CommandResult execute(ParameterContainer parameters) {
        String format = parameters.get(FORMAT_KEY);
        if (format == null)
            format = "PEM";
        String truststore = parameters.get(TRUSTSTORE_KEY);
        
        HashSet<X509Certificate> certs = new HashSet<>();
        
        final List<Role> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getAuthorizedRoles(getAuthenticationToken());
        final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
        for (final Role role : roles) {
            try {
                List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAuthenticationToken(), role.getRoleId());
                for (RoleMember member : roleMembers) {
                    int tokenIssuerId = member.getTokenIssuerId();
                    if (tokenIssuerId != RoleMember.NO_ISSUER) {
                        final CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                                member.getTokenIssuerId());
                        Certificate certificate = info.getCertificateChain().get(0);
                        if (certificate instanceof X509Certificate) {
                            certs.add((X509Certificate) certificate);
                        }
                    }
                }
            } catch (AuthorizationDeniedException e) {
                getLogger().info("Unable to access certificate for role:" + role.getRoleName());
            }
        }
        
        if (format.equals("PEM")) {
            try (FileOutputStream truststoreStream = new FileOutputStream(truststore)) {
                for (X509Certificate certificate : certs) {
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
                keystore.load(null, "changeit".toCharArray());
                for (X509Certificate certificate : certs) {
                    keystore.setCertificateEntry(CertTools.getSHA256FingerprintAsString(certificate.getEncoded()), certificate);
                }
                try (FileOutputStream truststoreStream = new FileOutputStream(truststore)) {
                    keystore.store(truststoreStream, "changeit".toCharArray());
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
                + "all the certificates used to match roles.\n\n"
                + "For PKCS12 and JKS, the truststore password is 'changeit'.";
    }

}
