package org.ejbca.core.protocol.ws.client.stress;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.util.PerformanceTest;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class BaseCommand {
    final protected JobData jobData;
    BaseCommand(JobData _jobData) {
        this.jobData = _jobData;
    }
    @Override
    public String toString() {
        return "Class \'" +this.getClass().getCanonicalName()+"' with this job data: "+ this.jobData.toString();
    }

    /**
     * @param certificateResponse
     * @throws CertificateException
     */
    protected boolean checkAndLogCertificateResponse(
            final CertificateResponse certificateResponse,
            final JobData jobData, final boolean validateUsername,
            final PerformanceTest.Log log
    ) throws CertificateException {
        X509Certificate cert = null;
        for ( final java.security.cert.Certificate tmp : CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(Base64.decode(certificateResponse.getData()))) ) {
            cert = (X509Certificate)tmp;
        }
        if ( cert==null ) {
            log.error("no certificate generated for user "+jobData.userName);
            return false;
        }
        final String commonName = DnComponents.getPartFromDN(cert.getSubjectX500Principal().getName(), "CN");
        if (validateUsername && !commonName.equals(jobData.userName)) {
            log.error("Cert not created for right user. Username: \""+jobData.userName+"\" Subject DN: \""+cert.getSubjectX500Principal()+"\".");
            return false;
        }
        jobData.userCertsGenerated.add(cert);
        log.info("Cert created. Subject DN: \""+cert.getSubjectX500Principal()+"\".");
        log.result(CertTools.getSerialNumber(cert));
        return true;
    }
}