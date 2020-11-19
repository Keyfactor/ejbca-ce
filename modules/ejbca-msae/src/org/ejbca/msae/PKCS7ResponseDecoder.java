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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;

/**
 * 
 */
public class PKCS7ResponseDecoder {

    Certificate[] ee_certs;

    public PKCS7ResponseDecoder(byte[] pkcs7fromejbca) throws SignatureException, CMSException, IOException, CertificateException, StoreException {
        CMSSignedData csd = new CMSSignedData(pkcs7fromejbca);
        @SuppressWarnings("unchecked")
        Store<X509CertificateHolder> certs = csd.getCertificates();
        ee_certs = CertTools.convertToX509CertificateArray(certs.getMatches(null));
        //ee_certs = certs.getCertificates(null).toArray(new Certificate[0]);
        if (ee_certs.length == 0) {
            throw new IOException("No certificates found");
        }

    }

    public X509Certificate getCertificate() {
        return (X509Certificate) ee_certs[0];
    }

    public int numCertificates() {
        return ee_certs.length;
    }

    public X509Certificate getCertificate(int index) {
        return (X509Certificate) ee_certs[index];
    }

    static byte[] getByteArrayFromInputStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        while ((bytes = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytes);
        }
        is.close();
        return baos.toByteArray();
    }

    public static void main(String[] argc) {
        try {
            FileReader fileReader = new FileReader(argc[0]);
            BufferedReader br = new BufferedReader(fileReader);
            StringBuffer input = new StringBuffer();
            String line;
            while (null != (line = br.readLine())) {
                if (line.endsWith("&#xD;")) {
                    line = line.substring(0, line.length() - "&#xD;".length());
                }
                input.append(line);
            }
            br.close();
            System.out.println("[" + input + "]");
            byte[] pkcs7bytes = Base64.decode(input.toString());

            Security.addProvider(new BouncyCastleProvider());
            //            PKCS7ResponseDecoder res = new PKCS7ResponseDecoder(getByteArrayFromInputStream(new FileInputStream(argc[0])));
            PKCS7ResponseDecoder res = new PKCS7ResponseDecoder(pkcs7bytes);
            int numCertificates = res.numCertificates();
            System.out.println("Num certificates: " + res.numCertificates());
            for (int i = 0; i < numCertificates; i++) {
                System.out.println("Certificate(" + i + ") = [" + res.getCertificate(i).toString() + "]");
            }
            if (argc.length == 2) {
                FileOutputStream fis = new FileOutputStream(argc[1]);
                fis.write(res.getCertificate().getEncoded());
                fis.close();
                System.out.println("File '" + argc[1] + "' written");
            }
        } catch (IOException | SignatureException | StoreException | CMSException | CertificateException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-3);
        }
    }
}
