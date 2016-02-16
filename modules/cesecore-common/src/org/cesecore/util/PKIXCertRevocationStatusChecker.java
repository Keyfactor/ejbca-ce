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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
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
 * A class to check whether a certificate is revoked or not using either OCSP or CRL. 
 * The revocation status will first be obtained using OCSP. If it turned out that that was not possible for 
 * some reason, a CRL will be used instead. If it was not possible to check the CRL for some reason, an 
 * exception will be thrown.
 * 
 * @version $Id$
 *
 */
public class PKIXCertRevocationStatusChecker extends PKIXCertPathChecker {

    private final Logger log = Logger.getLogger(PKIXCertRevocationStatusChecker.class);

    
    private String ocspUrl;
    private String crlUrl;
    private X509Certificate issuerCert;
    private Collection<X509Certificate> caCerts;
    
    private SingleResp ocspResponse=null;
    private Collection<CRL> crls=new ArrayList<CRL>();
    private boolean isCertificateRevoked = false;
    
    /**
     * Empty constructor. Since no specific parameters are specified, The certificate revocation status will be 
     * checked using a CRL fetch using a URL extracted from the certificate's CRL Distribution Points extension.
     */
    public PKIXCertRevocationStatusChecker() {
        this.ocspUrl = null;
        this.crlUrl = null;
        this.issuerCert = null;
        this.caCerts = null;
    }
    
    /**
     * @param ocspurl The URL to use when sending an OCSP request. If 'null', the OCSP URL will be extracted from 
     * the certificate's AuthorityInformationAccess extension if it exists.
     * @param crlurl The URL to fetch the CRL from. If 'null', the CRL URL will be extracted from the certificate's 
     * CRLDistributionPoints extension if exists.
     * @param issuerCert The certificate of the issuer of the certificate whose revocation status is to be checked. 
     * if 'null', the issuer certificate will be looked for among the certificates specified in 'cacerts'
     * @param cacerts A collection of certificates where one of them is the certificate of the issuer of the certificate 
     * whose status is to be checked. This parameter will be used only if 'issuerCert' is null
     */
    public PKIXCertRevocationStatusChecker(final String ocspurl, final String crlurl, final X509Certificate issuerCert, final Collection <X509Certificate> cacerts) {
        this.ocspUrl = ocspurl;
        this.crlUrl = crlurl;
        this.issuerCert = issuerCert;
        this.caCerts = cacerts;
    }
    
    @Override
    public void init(boolean forward) throws CertPathValidatorException {}

    @Override
    public boolean isForwardCheckingSupported() {
        // Not used
        return true;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }
    
    /**
     * @return The OCSP response containing the certificate status of the saught out certificate. Or 'null' if an OCSP response 
     * could not be obtained for any reason.
     */
    public SingleResp getOCSPResponse() {
        return this.ocspResponse;
    }
    
    /**
     * @return The CRLs that were checked. Or an empty Collection if no CRLs were checked 
     */
    public Collection<CRL> getcrls() {
        return this.crls;
    }
    
    /**
     * @return 'true' if either the OCSP response or the CRL check returned that the certificate is in fact revoked. 'false' otherwise
     */
    public boolean isCertificateRevoked() {
        return this.isCertificateRevoked;
    }
    
    /**
     * Resets the OCSP response, the checked CRLs and whether the certificate was revoked in case the same instance of this class is 
     * used to check the revocation status of more that one certificate.
     */
    private void clearResult() {
        this.ocspResponse=null;
        this.crls = new ArrayList<CRL>();
        this.isCertificateRevoked = false;
    }

    /**
     * Checks the revocation status of 'cert'; first by sending on OCSP request. If that fails for any reason, then through a CRL
     */
    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        
        clearResult();
        
        String ocspurl = getOcspUrl(cert);

        if(StringUtils.isNotEmpty(ocspurl)) {
            Certificate cacert = getCaCert(cert);
            if(cacert == null) {
                log.error("No issuer CA certificate was found. An issuer CA certificate is needed to create an OCSP request");
                fallBackToCrl(cert);
            }
            
            BigInteger certSerialnumber = CertTools.getSerialNumber(cert);
            String nonce = CertTools.getFingerprintAsString(cert)+System.currentTimeMillis();
            OCSPReq req = null;
            try {
                req = getOcspRequest(cacert, certSerialnumber, nonce);
            } catch (CertificateEncodingException | OCSPException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Failed to create OCSP request. " + e.getLocalizedMessage());
                }
                fallBackToCrl(cert);
                return;
                
            }
            
            // Send the request and receive a singleResponse
            SingleResp[] singleResps = null; 
            try {
                singleResps = getOCSPResponse(ocspurl, req.getEncoded(), nonce, OCSPRespBuilder.SUCCESSFUL, 200);
            } catch (OperatorCreationException | CertificateException | IOException | OCSPException  e) {
                if(log.isDebugEnabled()) {
                    log.debug("Failed to parse or verify OCSP response. " + e.getLocalizedMessage());
                }
                fallBackToCrl(cert);
                return;
            }
            
            if(singleResps == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Failed to verify certificate revocation status using OCSP.");
                }
                fallBackToCrl(cert);
                return;
            }
                
            SingleResp response = singleResps[0];
            CertificateID certId = response.getCertID();
            if(!certId.getSerialNumber().equals(certSerialnumber)) {
                if(log.isDebugEnabled()) {
                    log.debug("Certificate serialnumber in response does not match certificate serialnumber in request.");
                }
                fallBackToCrl(cert);
                return;
            }
            this.ocspResponse = response;
            CertificateStatus status = response.getCertStatus();
            if(log.isDebugEnabled()) {
                log.debug("The certificate status is: " + (status==null? "Good" : status.toString()));
            }
            if(status != null) {
                this.isCertificateRevoked = true;
                throw new CertPathValidatorException("Certificate with serialnumber " + CertTools.getSerialNumberAsString(cert) + " was revoked");
            }
        } else {
            fallBackToCrl(cert);
        }

        
    }
    
    /**
     * Check the revocation status of 'cert' using a CRL
     * @param cert the certificate whose revocation status is to be checked
     * @throws CertPathValidatorException
     */
    private void fallBackToCrl(final Certificate cert) throws CertPathValidatorException {
        if(log.isDebugEnabled()) {
            log.debug("Failed to check certificate revocation status using OCSP. Falling back to check using CRL");
        }

        ArrayList<String> crlUrls = getCrlUrl(cert);
        if(crlUrls.isEmpty()) {
            final String errmsg = "Failed to verify certificate status using the fallback CRL method. Could not find a CRL URL"; 
            log.error(errmsg);
            throw new CertPathValidatorException(errmsg);
        }
        if(log.isDebugEnabled()) {
            log.debug("Found " + crlUrls.size() + " CRL URLs");
        }
        
        CRL crl = null;
        for(String url : crlUrls) {
            crl = getCRL(url);
            if(crl != null) {
                this.crls.add(crl);
                if(crl.isRevoked(cert)) {
                    this.isCertificateRevoked = true;
                    throw new CertPathValidatorException("Certificate with serialnumber " + CertTools.getSerialNumberAsString(cert) + " was revoked");
                }
            }
        }
    }
    
    private CRL getCRL(final String crlurl) {
        CRL crl = null;
        try {
            final URL url = new URL(crlurl);
            final URLConnection con = url.openConnection();
            final InputStream is = con.getInputStream();
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            crl = (CRL)cf.generateCRL(is);
            is.close();
        } catch(IOException | CertificateException | CRLException e) { }
        return crl;
    }
    
    /**
     * Construct an OCSP request
     * @param cacert The certificate of the issuer of the certificate to be checked
     * @param certSerialnumber the serialnumber of the certificate to be checked
     * @return
     * @throws CertificateEncodingException
     * @throws OCSPException
     */
    private OCSPReq getOcspRequest(Certificate cacert, BigInteger certSerialnumber, final String nonce) throws CertificateEncodingException, OCSPException {
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), (X509Certificate) cacert, certSerialnumber));
        
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce.getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        return gen.build();
    }

    /**
     * Sends an OCSP request and returns the OCSP response
     */
    private SingleResp[] getOCSPResponse(final String ocspurl, final byte[] ocspPackage, final String nonce, int expectedOcspRespCode, int expectedHttpRespCode) 
            throws OCSPException, OperatorCreationException, CertificateException {
        if(log.isDebugEnabled()) {
            log.debug("Sending an OCSP requst to " + ocspurl);
        }
        
        OCSPResp response = null;
        HttpURLConnection con = null;
        try {
            final URL url = new URL(ocspurl);
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
                handleContentOfErrorStream(con.getErrorStream());
                return null; // if it is an http error code we don't need to test any more
            }

            InputStream is = con.getInputStream();
            response = new OCSPResp(IOUtils.toByteArray(is));
            is.close();
        
        } catch(IOException e) {
            log.info("Unable to get an OCSP response");
            if(con != null) {
                handleContentOfErrorStream(con.getErrorStream());
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

        // Check the nonce
        byte[] noncerep;
        try {
            noncerep = brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
        } catch (IOException e) {
            if(log.isDebugEnabled()) {
                log.debug("Failed to read extension from OCSP response. " + e.getLocalizedMessage());
            }
            return null;
        }
        if(noncerep == null) {
            log.warn("Sent an OCSP request containing a nonce, but the OCSP response does not contain a nonce");
            return null;
        }
        
        try {
            ASN1InputStream ain = new ASN1InputStream(noncerep);
            ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
            ain.close();
            if(!StringUtils.equals(nonce, new String(oct.getOctets()))) {
                log.warn("The nonce in the OCSP request and the OCSP response do not match");
                return null;
            }
        } catch (IOException e) {
            if(log.isDebugEnabled()) {
                log.debug("Failed to read extension from OCSP response. " + e.getLocalizedMessage());
            }
            return null;
        }
        
        SingleResp[] singleResps = brep.getResponses();
        if(singleResps.length==0) {
            return null;
        }
        return singleResps;        
    }
    
    /**
     * Reads the content of 'httpErrorStream' and ignores it. 
     */
    private void handleContentOfErrorStream(final InputStream httpErrorStream) {
        try {
            OutputStream os = new NullOutputStream();
            IOUtils.copy(httpErrorStream, os);
            httpErrorStream.close();
            os.close();
        } catch(IOException ex) {}
    }
    
    private String getOcspUrl(Certificate cert) {
        String ocspurl = this.ocspUrl;
        
        if(StringUtils.isEmpty(ocspurl)) {
            try {
                ocspurl = CertTools.getAuthorityInformationAccessOcspUrl(cert);
            } catch (CertificateParsingException e) {}
        }
        
        return ocspurl;
    }
    
    private ArrayList<String> getCrlUrl(final Certificate cert) {
        
        ArrayList<String> urls = new ArrayList<String>();
        
        if(StringUtils.isNotEmpty(this.crlUrl)) {
            urls.add(this.crlUrl);
        }
        
        ArrayList<String> crlUrlFromExtension = null;
        try {
            crlUrlFromExtension = (ArrayList<String>) CertTools.getCrlDistributionPoints(cert); 
        } catch (CertificateParsingException e1) { }
        
        if(crlUrlFromExtension != null) {
            urls.addAll(crlUrlFromExtension);
        }
        
        return urls; 
    }
    
    private X509Certificate getCaCert(final Certificate targetCert) {
        if(this.issuerCert != null) {
            return issuerCert;
        }
        
        if((this.caCerts==null) || (this.caCerts.isEmpty())) { // no CA specified
            return null;
        }
        
        Iterator<X509Certificate> caChainItr = caCerts.iterator();
        X509Certificate cacert = null;
        while(caChainItr.hasNext()) {
            cacert = caChainItr.next();
            if(isIssuerCA(targetCert, cacert)) {
                return cacert;
            }
        }
        return null;
    }
    
    private boolean isIssuerCA(final Certificate cert, final Certificate cacert) {
        if(!StringUtils.equals(CertTools.getIssuerDN(cert), CertTools.getSubjectDN(cacert))) {
            return false;
        }
        try {
            cert.verify(cacert.getPublicKey());
            return true;
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

}
