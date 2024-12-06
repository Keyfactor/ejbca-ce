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

package org.ejbca.core.protocol.ws.client.stress;

import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.util.PerformanceTest;

import java.security.KeyPairGenerator;

public class MultipleCertsRequestsForAUserCommand extends BaseCommand implements PerformanceTest.Command {
    final String caName;
    final String endEntityProfileName;
    final String certificateProfileName;
    final KeyPairGenerator kpg;

    public MultipleCertsRequestsForAUserCommand(EjbcaWS ejbcaWS, String caName, String endEntityProfileName, String certificateProfileName, JobData jobData, KeyPairGenerator kpg, PerformanceTest.Log log) throws Exception {
        super(ejbcaWS, jobData, log);
        this.caName = caName;
        this.endEntityProfileName = endEntityProfileName;
        this.certificateProfileName = certificateProfileName;
        this.kpg = kpg;
    }

    @Override
    public boolean doIt() throws Exception {
        boolean createUser = true;
        for (int i=0; i<50; i++) {
            EditUserCommand editUserCommand = new EditUserCommand(ejbcaWS, caName, endEntityProfileName, certificateProfileName, jobData, createUser, -1, log);
            if (!editUserCommand.doIt()) {
                log.error("MultiplePkcs10RequestsCommand failed for "+jobData.userName);
                return false;
            }
            createUser = false;
            Pkcs10RequestCommand pkcs10RequestCommand = new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData, log);
            if (!pkcs10RequestCommand.doIt()) {
                log.error("MultiplePkcs10RequestsCommand failed for "+this.jobData.userName);
                return false;
            }
        }
        return true;
    }

    @Override
    public String getJobTimeDescription() {
        return "Relative time spent creating a lot of certificates";
    }
}
