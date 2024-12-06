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
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.util.PerformanceTest;

import java.security.KeyPair;

public class Pkcs10RequestCommand extends BaseCommand implements PerformanceTest.Command {
    final private PKCS10CertificationRequest pkcs10;

    public Pkcs10RequestCommand(EjbcaWS _ejbcaWS, KeyPair keys, JobData _jobData, PerformanceTest.Log log) throws Exception {
        super(_ejbcaWS, _jobData, log);
        this.pkcs10 = CertTools.genPKCS10CertificationRequest(
                keys.getPublic().getAlgorithm().equals("RSA") ? "SHA1WithRSA" : "SHA256withECDSA",
                DnComponents.stringToBcX500Name("CN=NOUSED"), keys.getPublic(), new DERSet(), keys.getPrivate(), null);
    }

    @Override
    public boolean doIt() throws Exception {
        final CertificateResponse certificateResponse = this.ejbcaWS.pkcs10Request(this.jobData.userName, this.jobData.passWord,
                new String(Base64.encode(this.pkcs10.getEncoded())),null, org.ejbca.core.protocol.ws.common.CertificateHelper.RESPONSETYPE_CERTIFICATE);
        return checkAndLogCertificateResponse(certificateResponse, this.jobData, true);
    }

    @Override
    public String getJobTimeDescription() {
        return "";
    }
}
