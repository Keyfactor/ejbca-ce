package org.ejbca.core.protocol.ws.client.stress;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.protocol.ws.client.StressTestCommandBase;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
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

import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.util.PerformanceTest;

import java.math.BigInteger;

public class EditUserCommand extends BaseCommand implements PerformanceTest.Command {
    final private UserDataVOWS user;
    final private boolean doCreateNewUser;
    final private int bitsInCertificateSN;

    public EditUserCommand(
            EjbcaWS ejbcaWS,
            String caName,
            String endEntityProfileName,
            String certificateProfileName,
            JobData jobData,
            boolean doCreateNewUser,
            int bitsInCertificateSN,
            PerformanceTest.Log log
    ) {
        super(ejbcaWS, jobData, log);
        this.doCreateNewUser = doCreateNewUser;
        this.user = new UserDataVOWS();
        this.user.setClearPwd(true);
        this.user.setCaName(caName);
        this.user.setEmail(null);
        this.user.setSubjectAltName(null);
        this.user.setStatus(EndEntityConstants.STATUS_NEW);
        this.user.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        this.user.setEndEntityProfileName(endEntityProfileName);
        this.user.setCertificateProfileName(certificateProfileName);
        this.bitsInCertificateSN = bitsInCertificateSN;
    }
    @Override
    public boolean doIt() throws Exception {
        if ( this.doCreateNewUser ) {
            this.jobData.passWord = "foo123";
            if (jobData.forCvc) {
                this.jobData.userName = "S"+ StressTestCommandBase.nextCvcLong();
            } else {
                this.jobData.userName = "WS_STRESS_TEST_USER"+ StressTestCommandBase.nextLong();
            }
        }
        if ( this.bitsInCertificateSN>0 && this.doCreateNewUser ) {
            this.user.setCertificateSerialNumber(new BigInteger(this.bitsInCertificateSN, StressTestCommandBase.getRandom()));
        }
        this.user.setSubjectDN(this.jobData.getDN());
        this.user.setUsername(this.jobData.userName);
        this.user.setPassword(this.jobData.passWord);
        this.ejbcaWS.editUser(this.user);
        return true;
    }
    @Override
    public String getJobTimeDescription() {
        if ( this.doCreateNewUser ) {
            return "Relative time spent registering new users";
        }
        return "Relative time spent setting status of user to NEW";
    }
}
