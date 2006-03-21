/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

/** A simple OCSP lookup client used to query the OCSPUnidExtension. Attributes needed to call the client is a keystore
 * issued from the same CA as has issued the TLS server certificate of the OCSP/Lookup server.
 * The keystore must be a PKCS#12 file.
 * 
 * If requesting an Fnr and the fnr rturned is null, even though the OCSP code is good there can be several reasons:
 * 1.The client was not authorized to request an Fnr
 * 2.There was no Unid Fnr mapping available
 * 3.There was no Unid in the certificate (serialNumber DN component)
 *
 * @author Tomas Gustavsson, PrimeKey Solutions AB
 * @version $Id: OCSPUnidClient.java,v 1.7 2006-03-21 08:53:16 anatom Exp $
 *
 */
public class OCSPUnidClient {

	private String httpReqPath = null;
	private KeyStore ks = null;
	private String passphrase = null;
	
	/**  
	 * 
	 * @param ks KeyStore client keystore used to authenticate TLS client authentication
	 * @param pwd String password for the key store 
	 * @param ocspurl String url to the OCSP server, e.g. http://127.0.0.1:8080/ejbca/publicweb/status/ocsp 
	 */
	public OCSPUnidClient(KeyStore keystore, String pwd, String ocspurl) {
		this.httpReqPath = ocspurl;
		this.passphrase = pwd;
		this.ks = keystore;
		CertTools.installBCProvider();
	}
	
	/** 
	 * 
	 * @param ksfilename String Filename of PKCS#12 keystore used to authenticate TLS client authentication
	 * @param pwd String password for the key store 
	 * @param ocspurl String url to the OCSP server, e.g. http://127.0.0.1:8080/ejbca/publicweb/status/ocsp
	 * @throws NoSuchProviderException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	public OCSPUnidClient(String ksfilename, String pwd, String ocspurl) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		this.httpReqPath = ocspurl;
		this.passphrase = pwd;
		if (ksfilename != null) {
	        ks = KeyStore.getInstance("PKCS12", "BC");
	        ks.load(new FileInputStream(ksfilename), pwd.toCharArray());			
		}
		CertTools.installBCProvider();
	}

    /**
	 * 
	 * @param cert X509Certificate to query, the DN should contain serialNumber which is Unid to be looked up
	 * @param cacert CA certificate that issued the certificate to be queried
	 * @param getfnr if we should ask for a Unid-Fnr mapping or only query the OCSP server
	 * @return OCSPUnidResponse conatining the response and the fnr, can contain and an error code and the fnr can be null, never returns null.
	 */
	public OCSPUnidResponse lookup(X509Certificate cert, X509Certificate cacert, boolean getfnr) throws OCSPException, IOException, GeneralSecurityException {
        // See if we must try to get the ocsprul from the cert
        if (httpReqPath == null) {
            httpReqPath = CertTools.getAuthorityInformationAccessOcspUrl(cert);
            // If we didn't pass a url to the constructor and the cert does not have the URL, we will fail...
            if (httpReqPath == null) {
                OCSPUnidResponse ret = new OCSPUnidResponse();
                ret.setErrorCode(OCSPUnidResponse.ERROR_NO_OCSP_URI);
                return ret;
            }
        }
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, cacert, cert.getSerialNumber());
//        System.out.println("Generating CertificateId:\n"
//                + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
//                + " CA certificate\n"
//                + "      CA SubjectDN: '" + cacert.getSubjectDN().getName() + "'\n"
//                + "      SerialNumber: '" + cacert.getSerialNumber().toString(16) + "'\n"
//                + " CA certificate hashes\n"
//                + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
//                + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");
        gen.addRequest(certId);
        // Don't bother adding Unid extension if we are not using client authentication
        if (ks != null) {
            Hashtable exts = new Hashtable();
            X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("1")));
            exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
            gen.setRequestExtensions(new X509Extensions(exts));        	
        }
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        OCSPUnidResponse ret = sendOCSPPost(req.getEncoded());
        return ret;
	}

    //
    // Private helper methods
    //
    
    private OCSPUnidResponse sendOCSPPost(byte[] ocspPackage) throws IOException, OCSPException, GeneralSecurityException {
        // POST the OCSP request
        URL url = new URL(httpReqPath);
        HttpURLConnection con = (HttpURLConnection)getUrlConnection(url);
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = null;
        try {
            os = con.getOutputStream();
            os.write(ocspPackage);
        } finally {
            if (os != null) os.close();
        }
        OCSPUnidResponse ret = new OCSPUnidResponse();
        ret.setHttpReturnCode(con.getResponseCode());
        if (ret.getHttpReturnCode() != 200) {
        	if (ret.getHttpReturnCode() == 401) {
        		ret.setErrorCode(OCSPUnidResponse.ERROR_UNAUTHORIZED);
        	} else {
        		ret.setErrorCode(OCSPUnidResponse.ERROR_UNKNOWN);
        	}
        	return ret;
        }
        ByteArrayOutputStream baos = null;
        InputStream in = null;
        byte[] respBytes = null;
        try {
            baos = new ByteArrayOutputStream();
            // This works for small requests, and OCSP requests are small
            in = con.getInputStream();
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
            in.close();
            respBytes = baos.toByteArray();        	
        } finally {
        	if (baos != null) baos.close();
        	if (in != null) in.close();
        }
        if (respBytes == null) {
        	ret.setErrorCode(OCSPUnidResponse.ERROR_NO_RESPONSE);
        	return ret;
        }
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(respBytes));
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        if (!verify) {
        	ret.setErrorCode(OCSPUnidResponse.ERROR_INVALID_SIGNATURE);
        	return ret;
        }
        ret.setResp(response);
        String fnr = getFnr(brep);
        if (fnr != null) {
        	ret.setFnr(fnr);
        }
        return ret;
    }

    private String getFnr(BasicOCSPResp brep) throws IOException {
        byte[] fnrrep = brep.getExtensionValue(FnrFromUnidExtension.FnrFromUnidOid.getId());
        if (fnrrep == null) {
            return null;            
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(fnrrep));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        FnrFromUnidExtension fnrobj = FnrFromUnidExtension.getInstance(aIn.readObject());
        return fnrobj.getFnr();
    }

    private SSLSocketFactory getSSLFactory() throws GeneralSecurityException, IOException {

        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

        // Put the key and certs in the user keystore
        kmf.init(ks, passphrase.toCharArray());

        // Now make a truststore to verify the server
        KeyStore trustks = KeyStore.getInstance("jks");
        trustks.load(null, "foo123".toCharArray());
        // add trusted CA cert
        Enumeration en = ks.aliases();
        String alias = (String)en.nextElement();
        // If this alias is a trusted certificate entry, we don't want to fetch that, we want the key entry
        if (ks.isCertificateEntry(alias)) {
            if (en.hasMoreElements()) {
                alias = (String)en.nextElement();
            }
        }        Certificate[] certs = KeyTools.getCertChain(ks, alias);
        if (certs == null) {
            throw new IOException("Can not find a certificate entry in PKCS12 keystore for alias "+alias);
        }
        trustks.setCertificateEntry("trusted", certs[certs.length-1]);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustks);

        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return ctx.getSocketFactory();
    }

    /**
     * 
     * @param url
     * @return URLConnection
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private URLConnection getUrlConnection(URL url) throws IOException, GeneralSecurityException {
        URLConnection orgcon = url.openConnection();
        if (orgcon instanceof HttpsURLConnection) {
            HttpsURLConnection con = (HttpsURLConnection) orgcon;
            con.setHostnameVerifier(new SimpleVerifier());
            con.setSSLSocketFactory(getSSLFactory());
        } 
        return orgcon;
    }

    class SimpleVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
	
}
