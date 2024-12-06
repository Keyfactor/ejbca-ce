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

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.util.PerformanceTest;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class BaseCommand {
    final protected EjbcaWS ejbcaWS;
    final protected JobData jobData;
    final protected PerformanceTest.Log log;

    BaseCommand(EjbcaWS ejbcaWS, JobData jobData, PerformanceTest.Log log) {
        this.ejbcaWS = ejbcaWS;
        this.jobData = jobData;
        this.log = log;
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
            final JobData jobData,
            final boolean validateUsername
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