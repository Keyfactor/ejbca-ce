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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Dumps PEM or DER file as readable ASN1'
 * 
 * @version $Id$
 */
public class Asn1DumpCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(Asn1DumpCommand.class);
    private static final String FILENAME_KEY = "-f";

    //Register all parameters
    {
        final String filenameInstruction = "Filename of PEM encoded certificates, or of DER encoded ASN1";
        registerParameter(new Parameter(FILENAME_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                filenameInstruction));
    }
    
    @Override
    public String getMainCommand() {
        return "asn1dump";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String filename = parameters.get(FILENAME_KEY);
        boolean iscert = true;
        Collection<Certificate> coll = null;
        CryptoProviderTools.installBCProvider();
        try {
            try {
                coll = CertTools.getCertsFromPEM(filename);
                if (coll.isEmpty()) {
                    iscert = false;
                }
            } catch (CertificateParsingException e) {
                iscert = false;
            }
            if (!iscert) {
                ASN1InputStream ais = new ASN1InputStream(new FileInputStream(filename));
                try {
                    ASN1Primitive obj = ais.readObject();
                    ais.close();
                    String dump = ASN1Dump.dumpAsString(obj);
                    log.info(dump);
                    
                } catch (IOException e) {
                   //None of the above.
                    log.error("File " + filename + " does not seem to contain either a PEM or DER encoded certificate.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            } else {
                for (Certificate cert : coll) {
                    String dump = ASN1Dump.dumpAsString(cert);
                    log.info(dump);
                }
            }
        } catch (FileNotFoundException e) {
            log.error("Error: No such file " + filename);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Dumps PEM or DER encoded certificate as readable ASN.1";
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
