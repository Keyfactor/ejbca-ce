package org.ejbca.core.protocol.ws.client.stress;

import jakarta.xml.bind.DatatypeConverter;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.util.PerformanceTest;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static org.ejbca.core.protocol.ws.client.EJBCAWSRABaseCommand.REVOKATION_REASON_UNSPECIFIED;

public class RevokeCertBackdatedCommand extends BaseCommand implements PerformanceTest.Command {
    final String revoceTime;

    public RevokeCertBackdatedCommand(EjbcaWS ejbcaWS, JobData jobData, PerformanceTest.Log log) {
        super(ejbcaWS, jobData, log);
        final Calendar c = Calendar.getInstance();
        c.setTime(new Date(new Date().getTime()-1000*60*60*24));
        this.revoceTime = DatatypeConverter.printDateTime(c);
        log.info("Revoke time: "+this.revoceTime);
    }
    private void revokeBackdated( int i ) throws Exception {
        this.ejbcaWS.revokeCertBackdated(
                ((X509Certificate)jobData.userCertsToBeRevoked[i]).getIssuerX500Principal().getName(),
                ((X509Certificate)jobData.userCertsToBeRevoked[i]).getSerialNumber().toString(16),
                REVOKATION_REASON_UNSPECIFIED,
                this.revoceTime);
    }
    private void revoke( int i ) throws Exception {
        this.ejbcaWS.revokeCert(
                ((X509Certificate)jobData.userCertsToBeRevoked[i]).getIssuerX500Principal().getName(),
                ((X509Certificate)jobData.userCertsToBeRevoked[i]).getSerialNumber().toString(16),
                REVOKATION_REASON_UNSPECIFIED);
    }

    @Override
    public boolean doIt() throws Exception {
        for (int i=0; i<this.jobData.userCertsToBeRevoked.length; i++) {
            try {
                revokeBackdated(i);
            } catch (RevokeBackDateNotAllowedForProfileException_Exception e) {
                revoke(i);
                log.info("No back dating since not allowed for the profile.");
                continue;
            }
        }
        return true;
    }

    @Override
    public String getJobTimeDescription() {
        return "";
    }
}
