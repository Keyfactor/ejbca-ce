package org.ejbca.core.protocol.ws.client.stress;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.protocol.ws.client.StressTestCommandBase;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.util.PerformanceTest;

import java.math.BigInteger;

public class EditUserCommand extends BaseCommand implements PerformanceTest.Command {
    final private EjbcaWS ejbcaWS;
    final private UserDataVOWS user;
    final private boolean doCreateNewUser;
    final private int bitsInCertificateSN;

    public EditUserCommand(EjbcaWS _ejbcaWS, String caName, String endEntityProfileName, String certificateProfileName,
                    JobData _jobData, boolean _doCreateNewUser, int _bitsInCertificateSN) {
        super(_jobData);
        this.doCreateNewUser = _doCreateNewUser;
        this.ejbcaWS = _ejbcaWS;
        this.user = new UserDataVOWS();
        this.user.setClearPwd(true);
        this.user.setCaName(caName);
        this.user.setEmail(null);
        this.user.setSubjectAltName(null);
        this.user.setStatus(EndEntityConstants.STATUS_NEW);
        this.user.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        this.user.setEndEntityProfileName(endEntityProfileName);
        this.user.setCertificateProfileName(certificateProfileName);
        this.bitsInCertificateSN = _bitsInCertificateSN;
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
