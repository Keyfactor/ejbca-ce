/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Callable;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.util.CertTools;

/**
 * This internal class exists for the sole purpose of catching deadlocks in the HSM hardware.
 * 
 * @version $Id$
 */
public class HsmResponseThread implements Callable<BasicOCSPResp> {

    public static final long HSM_TIMEOUT_SECONDS = 30;

    private final BasicOCSPRespBuilder basicRes;
    private final String signingAlgorithm;
    private final PrivateKey signerKey;
    private final JcaX509CertificateHolder[] chain;
    private final String provider;
    private final Date producedAt;

    public HsmResponseThread(final BasicOCSPRespBuilder basicRes, final String signingAlgorithm, final PrivateKey signerKey,
            final X509Certificate[] chain, final String provider, final Date producedAt) throws OcspFailureException {
        this.basicRes = basicRes;
        this.signingAlgorithm = signingAlgorithm;
        this.signerKey = signerKey;
        this.provider = provider;
        this.producedAt = producedAt;
        try {
            this.chain = CertTools.convertToX509CertificateHolder(chain);
        } catch (CertificateEncodingException e) {
            throw new OcspFailureException(e);
        }
    }

    @Override
    public BasicOCSPResp call() throws OCSPException {
        try {
            /*
             * BufferingContentSigner defaults to allocating a 4096 bytes buffer. Since a rather large OCSP response (e.g. signed with 4K
             * RSA key, nonce and a one level chain) is less then 2KiB, this is generally a waste of allocation and garbage collection.
             * 
             * In high performance environments, the full OCSP response should in general be smaller than 1492 bytes to fit in a single
             * Ethernet frame.
             * 
             * Lowering this allocation from 20480 to 4096 bytes under ECA-4084 which should still be plenty.
             */
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(signingAlgorithm).setProvider(provider).build(signerKey), 20480);
            return basicRes.build(signer, chain, producedAt!=null? producedAt : new Date());
        } catch (OperatorCreationException e) {
            throw new OcspFailureException(e);
        }
    }
}
