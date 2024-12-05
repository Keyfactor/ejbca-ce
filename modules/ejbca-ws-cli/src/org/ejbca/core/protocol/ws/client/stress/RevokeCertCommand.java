package org.ejbca.core.protocol.ws.client.stress;

import com.keyfactor.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.util.PerformanceTest;

import java.security.cert.Certificate;

import static org.ejbca.core.protocol.ws.client.EJBCAWSRABaseCommand.REVOKATION_REASON_UNSPECIFIED;

public class RevokeCertCommand extends BaseCommand implements PerformanceTest.Command {

    public RevokeCertCommand(EjbcaWS ejbcaWS, JobData jobData, PerformanceTest.Log log) {
        super(ejbcaWS, jobData, log);
    }
    @Override
    public boolean doIt() throws Exception {
        for (int i=0; i<this.jobData.userCertsToBeRevoked.length; i++) {
            Certificate certificate = jobData.userCertsToBeRevoked[i];
            String issuerDN = CertTools.getIssuerDN(certificate);
            ejbcaWS.revokeCert(
                    issuerDN,
                    CertTools.getSerialNumberAsString(jobData.userCertsToBeRevoked[i]),
                    REVOKATION_REASON_UNSPECIFIED
            );
        }
        return true;
    }

    @Override
    public String getJobTimeDescription() {
        return "Relative time spent revoking certificates.";
    }
}
