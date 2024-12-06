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

import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.util.PerformanceTest;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

public class ListCertsCommand extends BaseCommand implements PerformanceTest.Command {
    public ListCertsCommand(EjbcaWS ejbcaWS, JobData jobData, PerformanceTest.Log log) {
        super(ejbcaWS, jobData, log);
    }

    @Override
    public boolean doIt() throws Exception {
        final List<Certificate> result = this.ejbcaWS.findCerts(this.jobData.userName, true);
        final Iterator<Certificate> i = result.iterator();
        this.jobData.userCertsToBeRevoked = new X509Certificate[result.size()];
        for( int j=0; i.hasNext(); j++ ) {
            this.jobData.userCertsToBeRevoked[j] = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.decode(i.next().getCertificateData())));
        }
        if ( this.jobData.userCertsToBeRevoked.length < 1 ) {
            this.jobData.userCertsToBeRevoked = this.jobData.userCertsGenerated.toArray(new X509Certificate[this.jobData.userCertsGenerated.size()]);
        }
        this.jobData.userCertsGenerated.clear();
        if ( this.jobData.userCertsToBeRevoked.length < 1 ) {
            log.error("no cert found for user "+this.jobData.userName);
            return false;
        }

        return true;
    }

    @Override
    public String getJobTimeDescription()  {
        return "Relative time spent finding certs for user.";
    }
}
