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

package org.ejbca.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.certificates.util.AlgorithmTools;

/**
 * CMS utils.
 * @version $Id$
 *
 */
public class CMS {
    final static private Logger log = Logger.getLogger(CMS.class);
    final static private int bufferSize = 0x20000;
    private static void fromInToOut( InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[bufferSize];
        while (true) {
            int len = in.read(buf);
            if ( len<0 ) {
                break;
            }
            out.write(buf,0, len);
        }
        out.close();
    }
    /**
     * @param is data to be encrypted
     * @param os encrypted data
     * @param cert certificate with the public key to be used for the encryption
     * @param symmAlgOid the symmetric encryption algorithm to use, for example CMSEnvelopedGenerator.AES128_CBC
     * @throws Exception
     */
    public static void encrypt(final InputStream is, final OutputStream os, final X509Certificate cert, final String symmAlgOid) throws Exception {
        final InputStream bis = new BufferedInputStream(is, bufferSize);
        final OutputStream bos = new BufferedOutputStream(os, bufferSize);
        final CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator("hej".getBytes(), cert.getPublicKey()));
        final OutputStream out = edGen.open(bos, symmAlgOid, "BC");
        fromInToOut(bis, out);
        bos.close();
        os.close();
    }
    /**
     * @param is data to be decrypted
     * @param os decrypted data
     * @param key to be used for the decryption
     * @param providerName the provider that should do the decryption
     * @throws Exception
     */
    public static void decrypt(final InputStream is, OutputStream os, Key key, String providerName) throws Exception  {
        final InputStream bis = new BufferedInputStream(is, bufferSize);
        final OutputStream bos = new BufferedOutputStream(os, bufferSize);
        @SuppressWarnings("unchecked")
        final Iterator<RecipientInformation>  it = new CMSEnvelopedDataParser(bis).getRecipientInfos().getRecipients().iterator();
        if (it.hasNext()) {
            final RecipientInformation recipient = it.next();
            final CMSTypedStream recData = recipient.getContentStream(key, providerName);
            final InputStream ris = recData.getContentStream();
            fromInToOut(ris, bos);
        }
        os.close();
    }
    /**
     * @param is data to be signed
     * @param os signed data
     * @param key to do be used for signing
     * @param providerName the provider that should do the signing
     * @throws Exception
     */
    public static void sign(final InputStream is, OutputStream os, PrivateKey key, String providerName, X509Certificate cert) throws Exception {
        final InputStream bis = new BufferedInputStream(is, bufferSize);
        final OutputStream bos = new BufferedOutputStream(os, bufferSize);
        final CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
        ASN1ObjectIdentifier oid = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, key.getAlgorithm());

        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromOID(oid);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithmName).setSecureRandom(new SecureRandom());
        ContentSigner contentSigner = signerBuilder.build(key);
        if ( cert!=null ) {      
            gen.addSignerInfoGenerator(builder.build(contentSigner, cert));          
        } else {
            gen.addSignerInfoGenerator(builder.build(contentSigner, "hej".getBytes()));          
        }
        final OutputStream out = gen.open(bos, true);
        fromInToOut(bis, out);
        bos.close();
        os.close();
    }
    public static class VerifyResult {
        public final Date signDate;
        public final boolean isVerifying;
        public final SignerId signerId;
        public VerifyResult(Date _signDate, boolean _isVerifying, SignerId _signerId) {
            this.signDate = _signDate;
            this.isVerifying = _isVerifying;
            this.signerId = _signerId;
        }
    }
    /**
     * @param is signed data to be verified
     * @param os signature removed from signed data
     * @param cert the certificate with the public key that should do the verification
     * @return true if the signing was to with the private key corresponding to the public key in the certificate.
     * @throws Exception
     */
    public static VerifyResult verify(final InputStream is, OutputStream os, X509Certificate cert) throws Exception  {
        final InputStream bis = new BufferedInputStream(is, bufferSize);
        final OutputStream bos = new BufferedOutputStream(os, bufferSize);
        final CMSSignedDataParser sp = new CMSSignedDataParser(new BcDigestCalculatorProvider(), bis);
        final CMSTypedStream sc = sp.getSignedContent();
        final InputStream ris = sc.getContentStream();
        fromInToOut(ris, bos);
        os.close();
        sc.drain();
        @SuppressWarnings("rawtypes")
        final Iterator  it = sp.getSignerInfos().getSigners().iterator();
        if ( !it.hasNext() ) {
            return null;
        }
        final SignerInformation signerInfo = (SignerInformation)it.next();
        final Attribute attribute = (Attribute)signerInfo.getSignedAttributes().getAll(CMSAttributes.signingTime).get(0);
        final Date date = Time.getInstance(attribute.getAttrValues().getObjectAt(0).toASN1Primitive()).getDate();
        final SignerId id = signerInfo.getSID();
        boolean result = false;
        try {
            result = signerInfo.verify(cert, "BC");
        } catch ( Throwable t ) { // NOPMD
            log.debug("Exception when verifying", t);
        }
        return new VerifyResult(date, result, id);            
    }
}
