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
package org.cesecore.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;

/**
 * This class is used to check whether a specific certificate is revoked or not using either 
 * a CRL or an OCSP request.
 * 
 * @version $Id$
 *
 */
public class CertificateRevocationStatusVerifier {

    public static final String VERIFICATION_METHOD_CRL = "crl";
    public static final String VERIFICATION_METHOD_OCSP = "ocsp";
    
    private final Logger log = Logger.getLogger(CertificateRevocationStatusVerifier.class);
    
    private String method;
    private String url;
    
    private SingleResp ocspResponse=null;
    private String httpErrResponse = "";

    /**
     * A CertificateRevocationStatusVerifier constructor to check the revocation status of a 
     * certificate through CRL
     * 
     * @param crlUrl
     */
    public CertificateRevocationStatusVerifier(final String crlUrl) {
        this.method=VERIFICATION_METHOD_CRL;
        this.url=crlUrl;
    }
    
    public CertificateRevocationStatusVerifier(final String method, final String url) {
        this.method=method;
        this.url=url;
    }
    
    public SingleResp getOCSPResponse() {
        return this.ocspResponse;
    }
    
    public String getHttpErrorContent() {
        return this.httpErrResponse;
    }
    
    /**
     * 
     * @param cert The certificate whose status will be checked
     * @param cacert The certificate of the issuer of the certificate to be checked
     * @return
     * @throws CRLException When there is a problem with generating or reading the CRL
     * @throws OCSPException When failed to create the OCSP request or failed to parse or read the OCSP response
     */
    public boolean isCertificateRevoked(final X509Certificate cert, final X509Certificate cacert) throws 
                CRLException, OCSPException {

        if((this.method == null) || (this.url == null)) {
            throw new IllegalArgumentException("Either the verification method or the verification URL or both of them are not set");
        }
        
        if(log.isDebugEnabled()) {
            log.debug("Checking revocation status of certificate with SubjectDN: " + CertTools.getSubjectDN(cert) + " - IssuerDN: " + CertTools.getIssuerDN(cert));
        }
        BigInteger certSerialnumber = CertTools.getSerialNumber(cert);
    
        if(StringUtils.equals(VERIFICATION_METHOD_OCSP, this.method)) {
            log.info("Using OCSP to verify the signing certificate revocation status");
            if(log.isDebugEnabled()) {
                log.debug("Using OCSP URL: " + this.url);
            }            

            OCSPReq req = null;
            try {
                req = getOcspRequest(cacert, certSerialnumber);
            } catch (CertificateEncodingException | OCSPException e) {
                throw new OCSPException("Failed to create OCSP request", e);
            }
            
            // Send the request and receive a singleResponse
            SingleResp[] singleResps = null; 
            try {
                singleResps = getOCSPResponse(req.getEncoded(), OCSPRespBuilder.SUCCESSFUL, 200);
            } catch (OperatorCreationException | CertificateException | IOException e) {
                throw new OCSPException("Failed to parse or verify OCSP response", e);
            }
            
            if(singleResps == null) {
                throw new OCSPException("Failed to verify certificate revocation status using OCSP. Received HTTP Error: " + getHttpErrorContent());
            }
                
            SingleResp response = singleResps[0];
            CertificateID certId = response.getCertID();
            if(!certId.getSerialNumber().equals(certSerialnumber)) {
                throw new OCSPException("Certificate serialnumber in response does not match certificate serialnumber in request.");
            }
            this.ocspResponse = response;
            CertificateStatus status = response.getCertStatus();
            if(log.isDebugEnabled()) {
                log.debug("The certificate status is: " + (status==null? "Good" : status.toString()));
            }
            return status!=null;
        } else if (StringUtils.equals(VERIFICATION_METHOD_CRL, this.method)) {
            log.info("Using CRL to verify the signing certificate revocation status");
            boolean isRevoked = true;
            if(log.isDebugEnabled()) {
                log.debug("Using CRL URL: " + this.url);
            }
            
            URLConnection con = null;
            try {
                URL url = new URL(this.url);
                con = url.openConnection();
                InputStream is = con.getInputStream();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                CRL crl = (CRL)cf.generateCRL(is);
                is.close();
                isRevoked = crl.isRevoked(cert);
                if(log.isDebugEnabled()) {
                    log.debug("The signing certificate is revoked in CRL: " + isRevoked);
                }
            } catch(IOException | CertificateException e) {
                throw new CRLException("Unable to read CRL from " + this.url, e);
            }
            return isRevoked;
        
        } else {
            throw new IllegalArgumentException("Unrecognized method to check revocation status of CMP message signing certificate: " + method);
        }
    }
    
    private OCSPReq getOcspRequest(X509Certificate cacert, BigInteger certSerialnumber) throws CertificateEncodingException, OCSPException {
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, certSerialnumber));
        return gen.build();
    }

    /**
     * 
     * @param ocspPackage The OCSP package to send
     * @param expectedOcspRespCode The expected OCSP response code
     * @param expectedHttpRespCode The expected HTTP response code
     * @return
     * @throws OCSPException When failed to parse  or verify the OCSP response
     * @throws OperatorCreationException When failed to parse  or verify the OCSP response
     * @throws CertificateException When failed to parse  or verify the OCSP response
     */
    private SingleResp[] getOCSPResponse(byte[] ocspPackage, int expectedOcspRespCode, int expectedHttpRespCode) throws OCSPException, OperatorCreationException, CertificateException {
        if(log.isDebugEnabled()) {
            log.debug("Sending an OCSP requst to " + this.url);
        }
        
        OCSPResp response = null;
        HttpURLConnection con = null;
        try {
            final URL url = new URL(this.url);
            con = (HttpURLConnection)url.openConnection();
            // we are going to do a POST
            con.setDoOutput(true);
            con.setRequestMethod("POST");

            // POST it
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            OutputStream os = con.getOutputStream();
            os.write(ocspPackage);
            os.close();
        
        
            final int httpRespCode = ((HttpURLConnection)con).getResponseCode();
            if (httpRespCode != expectedHttpRespCode) {
                log.info("HTTP response from OCSP request was " + httpRespCode + ". Expected " + expectedHttpRespCode );
                setContentOfErrorStream(con.getErrorStream());
                return null; // if it is an http error code we don't need to test any more
            }

            InputStream is = con.getInputStream();
            response = new OCSPResp(IOUtils.toByteArray(is));
            is.close();
        
        } catch(IOException e) {
            log.info("Unable to get an OCSP response");
            if(con != null) {
                setContentOfErrorStream(con.getErrorStream());
            }
            return null;
        }
        
        if (expectedOcspRespCode != 0) {
            if(response.getResponseObject() != null) {
                log.warn("According to RFC 2560, responseBytes are not set on error, but we got some.");    
            }
            return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
        }
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        if (brep==null) {
            log.warn("Cannot extract OCSP response object. OCSP response status: " + response.getStatus());
            return null;
        }
        X509CertificateHolder[] chain = brep.getCerts();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().build(chain[0]));
        if(!verify) {
            log.warn("OCSP response signature was not valid");
            return null;
        }
        // Check nonce (if we sent one)
        //if (nonce != null) {
        //    byte[] noncerep = brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
        //    if(noncerep != null) {
        //        ASN1InputStream ain = new ASN1InputStream(noncerep);
        //        ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
        //        ain.close();
        //    }
        //}
        SingleResp[] singleResps = brep.getResponses();
        if(singleResps.length==0) {
            return null;
        }
        return singleResps;        
    }
    
    private void setContentOfErrorStream(final InputStream httpErrorStream) {
        try {
            String res = IOUtils.toString(httpErrorStream);
            httpErrorStream.close();
            if(!StringUtils.isEmpty(res)) {
                this.httpErrResponse = res;
            }
            
        } catch(IOException ex) {}
    }

}