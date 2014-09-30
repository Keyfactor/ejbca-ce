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

import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Shows info about a CA.
 *
 * @version $Id$
 */
public class CaInfoCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaInfoCommand.class);
    
    private static final String CA_NAME_KEY = "--caname";
    
    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
    }
    
    @Override
    public String getMainCommand() {
        return "info";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        CryptoProviderTools.installBCProvider();
        String caname = parameters.get(CA_NAME_KEY);
        CAInfo cainfo = getCAInfo(getAuthenticationToken(), caname);
        if (cainfo != null) {
            ArrayList<Certificate> chain = new ArrayList<Certificate>(getCertChain(getAuthenticationToken(), caname));
            getLogger().info("CA name: " + caname);
            getLogger().info("CA type: " + cainfo.getCAType());
            getLogger().info("CA ID: " + cainfo.getCAId());
            getLogger().info("CA CRL Expiration Period: " + cainfo.getCRLPeriod());
            getLogger().info("CA CRL Issue Interval: " + cainfo.getCRLIssueInterval());
            getLogger().info("CA Description: " + cainfo.getDescription());

            if (chain.size() < 2) {
                getLogger().info("This is a Root CA.");
            } else {
                getLogger().info("This is a subordinate CA.");
            }

            getLogger().info("Size of chain: " + chain.size());
            if (chain.size() > 0) {
                Certificate rootcert = chain.get(chain.size() - 1);
                getLogger().info("Root CA DN: " + CertTools.getSubjectDN(rootcert));
                getLogger().info("Root CA id: " + CertTools.getSubjectDN(rootcert).hashCode());
                getLogger().info("Certificate valid from: " + CertTools.getNotBefore(rootcert));
                getLogger().info("Certificate valid to: " + CertTools.getNotAfter(rootcert));
                getLogger().info("Root CA key algorithm: " + rootcert.getPublicKey().getAlgorithm());
                getLogger().info("Root CA key size: " + KeyTools.getKeyLength(rootcert.getPublicKey()));
                if (rootcert.getPublicKey() instanceof ECPublicKey) {
                    if (((ECPublicKey) rootcert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                        getLogger().info(
                                "Root CA ECDSA key spec: " + ((ECNamedCurveSpec) ((ECPublicKey) rootcert.getPublicKey()).getParams()).getName());
                    }
                }
                for (int i = chain.size() - 2; i >= 0; i--) {
                    Certificate cacert = chain.get(i);
                    getLogger().info("CA DN: " + CertTools.getSubjectDN(cacert));
                    getLogger().info("Certificate valid from: " + CertTools.getNotBefore(cacert));
                    getLogger().info("Certificate valid to: " + CertTools.getNotAfter(cacert));
                    getLogger().info("CA key algorithm: " + cacert.getPublicKey().getAlgorithm());
                    getLogger().info("CA key size: " + KeyTools.getKeyLength(cacert.getPublicKey()));
                    if (cacert.getPublicKey() instanceof ECPublicKey) {
                        if (((ECPublicKey) cacert.getPublicKey()).getParams() instanceof ECNamedCurveSpec) {
                            getLogger()
                                    .info("CA ECDSA key spec: " + ((ECNamedCurveSpec) ((ECPublicKey) cacert.getPublicKey()).getParams()).getName());
                        }
                    }
                }
            }
        } else {
            getLogger().info("No CA named '" + caname + "' was found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;
    }
    
    @Override
    public String getCommandDescription() {
        return "Shows info about a CA";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
