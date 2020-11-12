/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.Store;
import org.cesecore.util.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class CertUtils {

    final private static String BEGINCERTIFICATE = "-----BEGIN CERTIFICATE-----";
    final private static String ENDCERTIFICATE = "-----END CERTIFICATE-----";
    final private static String BEGINPKCS7 = "-----BEGIN PKCS7-----";
    final private static String ENDPKCS7 = "-----END PKCS7-----";

    public static Collection<X509CertificateHolder> parseP7B(InputStream is) throws CMSException, IOException {

        final InputStreamReader isr = new InputStreamReader(is);
        final PEMParser parser = new PEMParser(isr);

        final ContentInfo info = (ContentInfo) parser.readObject();
        final CMSSignedData csd = new CMSSignedData(info);
        @SuppressWarnings("unchecked")
        final Store<X509CertificateHolder> certstore = csd.getCertificates();
        final Collection<X509CertificateHolder> collection = certstore.getMatches(null);

        parser.close();
        return collection;
    }

    private static byte[] getFirstCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {

        if (null != collection) {
            final X509CertificateHolder certholder = collection.iterator().next();
            final X509Certificate x509cert = new JcaX509CertificateConverter().getCertificate(certholder);
            return Base64.encode(x509cert.getEncoded());
        }

        return null;
    }

    public static byte[] getPKCS7Certificate(InputStream is) throws CertificateException, IOException, CMSException {

        final InputStreamReader isr = new InputStreamReader(is);
        final PEMParser parser = new PEMParser(isr);

        final ContentInfo info = (ContentInfo) parser.readObject();
        final CMSSignedData csd = new CMSSignedData(info);

        return csd.getEncoded();
    }

    public static String getPEMCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {
        final byte[] b64 = CertUtils.getFirstCertificate(collection);
        return BEGINCERTIFICATE + "\n" + new String(b64) + "\n" + ENDCERTIFICATE;
    }

    public static String getPEMCertificate(byte[] bytes) {
        final byte[] b64 = Base64.encode(bytes);
        return BEGINCERTIFICATE + "\n" + new String(b64) + "\n" + ENDCERTIFICATE;
    }

    public static String getPKCS7PEMCertificate(byte[] bytes) {
        final byte[] b64 = Base64.encode(bytes);
        return BEGINPKCS7 + "\n" + new String(b64) + "\n" + ENDPKCS7;
    }

    static byte[] getFirstCertificateFromPKCS7(byte[] pkcs7) throws CMSException, IOException {
        byte[] firstCertificate = null;

        final CMSSignedData csd = new CMSSignedData(pkcs7);
        @SuppressWarnings("unchecked")
        final Store<X509CertificateHolder> certstore = csd.getCertificates();
        final Collection<X509CertificateHolder> collection = certstore.getMatches(null);

        final Iterator<X509CertificateHolder> ci = collection.iterator();
        if (ci.hasNext()) {
            firstCertificate = ci.next().getEncoded();
        }

        return firstCertificate;
    }
}
