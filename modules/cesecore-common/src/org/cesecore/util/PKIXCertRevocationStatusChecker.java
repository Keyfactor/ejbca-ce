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
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
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
    private CRL crl=null;

    /**
     * With this constructor, the certificate revocation status will be checked using a CRL fetched using a URL 
     * extracted from the certificate's CRL Distribution Points extension.
     * 
     * @param issuerCert The certificate of the issuer of the certificate whose revocation status is to be checked. 
     * if 'null', the issuer certificate will be looked for among the certificates specified in 'cacerts'
     * @param cacerts A collection of certificates where one of them is the certificate of the issuer of the certificate 
     * whose status is to be checked. This parameter will be used only if 'issuerCert' is null

     */
    public PKIXCertRevocationStatusChecker(final X509Certificate issuerCert, final Collection <X509Certificate> cacerts) {
        this.ocspUrl = null;
        this.crlUrl = null;
        this.issuerCert = issuerCert;
        this.caCerts = cacerts;
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
        ArrayList<String> exts = new ArrayList<String>();
        exts.add(Extension.cRLDistributionPoints.getId());
        exts.add(Extension.authorityInfoAccess.getId());
        return new HashSet<String>(exts);
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
    public CRL getcrl() {
        return this.crl;
    }
    
    /**
     * Resets the OCSP response, the checked CRLs and whether the certificate was revoked in case the same instance of this class is 
     * used to check the revocation status of more that one certificate.
     */
    private void clearResult() {
        this.ocspResponse=null;
        this.crl = null;
    }

    /**
     * Checks the revocation status of 'cert'; first by sending on OCSP request. If that fails for any reason, then through a CRL
     */
    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        
        clearResult();
        Certificate cacert = getCaCert(cert);
        if(cacert == null) {
            final String msg = "No issuer CA certificate was found. An issuer CA certificate is needed to create an OCSP request and to get the right CRL"; 
            log.info(msg);
            throw new CertPathValidatorException(msg);
        }
        
        ArrayList<String> ocspurls = getOcspUrls(cert);
        if(!ocspurls.isEmpty()) {
            BigInteger certSerialnumber = CertTools.getSerialNumber(cert);
            String nonce = CertTools.getFingerprintAsString(cert)+System.currentTimeMillis();
            OCSPReq req = null;
            try {
                req = getOcspRequest(cacert, certSerialnumber, nonce);
            } catch (CertificateEncodingException | OCSPException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Failed to create OCSP request. " + e.getLocalizedMessage());
                }
                fallBackToCrl(cert, CertTools.getSubjectDN(cacert));
                return;
                
            }
            
            SingleResp ocspResp = null;
            for(String url : ocspurls) {
                ocspResp = getOCSPResponse(url, req, cert, nonce, OCSPRespBuilder.SUCCESSFUL, 200);
                if(ocspResp != null) {
                    log.info("Obtained OCSP response from " + url);
                    break;
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("Failed to obtain an OCSP reponse from " + url);
                    }
                }
            }
            
            if(ocspResp==null) {
                log.info("Failed to check certificate revocation status using OCSP. Falling back to check using CRL");
                fallBackToCrl(cert, CertTools.getSubjectDN(cacert));
            } else {
                CertificateStatus status = ocspResp.getCertStatus();
                this.ocspResponse = ocspResp;
                if(log.isDebugEnabled()) {
                    log.debug("The certificate status is: " + (status==null? "Good" : status.toString()));
                }
                if(status != null) { // status==null -> certificate OK
                    throw new CertPathValidatorException("Certificate with serialnumber " + CertTools.getSerialNumberAsString(cert) + " was revoked");
                }
                
                if(unresolvedCritExts != null) {
                    unresolvedCritExts.remove(Extension.authorityInfoAccess.getId());
                }
            }

        } else {
            fallBackToCrl(cert, CertTools.getSubjectDN(cacert));
            
            if(unresolvedCritExts != null) {
                unresolvedCritExts.remove(Extension.cRLDistributionPoints.getId());
            }
        }

    }
    
    /**
     * Check the revocation status of 'cert' using a CRL
     * @param cert the certificate whose revocation status is to be checked
     * @throws CertPathValidatorException
     */
    private void fallBackToCrl(final Certificate cert, final String issuerDN) throws CertPathValidatorException {
        final ArrayList<String> crlUrls = getCrlUrl(cert);
        if(crlUrls.isEmpty()) {
            final String errmsg = "Failed to verify certificate status using the fallback CRL method. Could not find a CRL URL"; 
            log.info(errmsg);
            throw new CertPathValidatorException(errmsg);
        }
        if(log.isDebugEnabled()) {
            log.debug("Found " + crlUrls.size() + " CRL URLs");
        }
        
        CRL crl = null;
        for(String url : crlUrls) {
            crl = getCRL(url);
            if(crl != null) {
                if(isCorrectCRL(crl, issuerDN)) {
                    final boolean isRevoked = crl.isRevoked(cert);
                    this.crl = crl;
                    if(isRevoked) {
                        throw new CertPathValidatorException("Certificate with serialnumber " + CertTools.getSerialNumberAsString(cert) + " was revoked");
                    }
                    break;
                }
            }
        }
        if(this.crl==null) {
            throw new CertPathValidatorException("Failed to verify certificate status using CRL. Could not find a CRL issued by " + issuerDN + " reasonably lately");
        }
    }
    
    private boolean isCorrectCRL(final CRL crl, final String issuerDN) {
        if(!(crl instanceof X509CRL)) {
            return false;
        }
        
        X509CRL x509crl = (X509CRL) crl;
        if(!StringUtils.equals(issuerDN, CertTools.getIssuerDN(x509crl))) {
            return false;
        }
        
        final Date now = new Date(System.currentTimeMillis());
        final Date nextUpdate = x509crl.getNextUpdate();
        if(nextUpdate!=null) {
            if(nextUpdate.after(now)) {
                return true;
            }
            
            if(log.isDebugEnabled()) {
                log.debug("CRL issued by " + issuerDN + " is out of date");
            }
            return false;
        }
        
        final Date thisUpdate = x509crl.getThisUpdate();
        if(thisUpdate!=null) {
            final GregorianCalendar gc = new GregorianCalendar();
            gc.setTime(now);
            gc.add(Calendar.HOUR, 1);
            final Date expire = gc.getTime();
            
            if(expire.before(now)) {
                if(log.isDebugEnabled()) {
                    log.debug("Could not find when CRL issued by " + issuerDN + " should be updated and this CRL is over one hour old. Not using it");
                }
                return false;
            }
            
            log.warn("Could not find when CRL issued by " + issuerDN + " should be updated, but this CRL was issued less than an hour ago, so we are using it");
            return true;
        }
            
        if(log.isDebugEnabled()) {
            log.debug("Could not check issuance time for CRL issued by " + issuerDN);
        }
        return false;
    }
    
    private CRL getCRL(final String crlurl) {
        CRL crl = null;
        try {
            final URL url = new URL(crlurl);
            final URLConnection con = url.openConnection();
            final InputStream is = con.getInputStream();
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            crl = cf.generateCRL(is);
            is.close();
            log.info("Downloaded CRL from " + url);
        } catch(IOException | CertificateException | CRLException e) {
            if(log.isDebugEnabled()) {
                log.debug("Fetching CRL from " + crlurl + " failed. " + e.getLocalizedMessage());
            }
        }
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
     * Sends an OCSP request, gets a response and verifies the response as much as possible before returning it to the caller.
     * 
     * @return The OCSP response, or null of no correct response could be obtained.
     */
    private SingleResp getOCSPResponse(final String ocspurl, final OCSPReq ocspRequest, final Certificate cert, final String nonce, int expectedOcspRespCode, int expectedHttpRespCode) {
        if(log.isDebugEnabled()) {
            log.debug("Sending OCSP request to " + ocspurl + " regarding certificate with SubjectDN: " + CertTools.getSubjectDN(cert) 
                        + " - IssuerDN: " + CertTools.getIssuerDN(cert));
        }
        
        //----------------------- Open connection and send the request --------------//
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
            os.write(ocspRequest.getEncoded());
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
            log.info("Unable to get an OCSP response. " + e.getLocalizedMessage());
            if(con != null) {
                handleContentOfErrorStream(con.getErrorStream());
            }
            return null;
        }
        
        
        
        // ------------ Verify the response signature --------------//
        BasicOCSPResp brep = null;
        try {
            brep = (BasicOCSPResp) response.getResponseObject();

            if ((expectedOcspRespCode != OCSPRespBuilder.SUCCESSFUL) && (brep!=null)) {
                log.warn("According to RFC 2560, responseBytes are not set on error, but we got some.");    
                return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
            }
        
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
        } catch (OCSPException | OperatorCreationException | CertificateException e) {
            if(log.isDebugEnabled()) {
                log.debug("Failed to obtain or verify OCSP response. " + e.getLocalizedMessage());
            }
            return null;
        }

        // ------------- Verify the nonce ---------------//
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
        
        
        // ------------ Extract the single response and verify that it concerns a cert with the right serialnumber ----//
        SingleResp[] singleResps = brep.getResponses();
        if((singleResps==null) || (singleResps.length==0)) {
            if(log.isDebugEnabled()) {
                log.debug("The OCSP response object contained no responses.");
            }
            return null;
        }
        
        SingleResp singleResponse = singleResps[0];
        CertificateID certId = singleResponse.getCertID();
        if(!certId.getSerialNumber().equals(CertTools.getSerialNumber(cert))) {
            if(log.isDebugEnabled()) {
                log.debug("Certificate serialnumber in response does not match certificate serialnumber in request.");
            }
            return null;
        }
        
        // ------------ Return the sigle response ---------------//
        return singleResponse;        
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
    
    private ArrayList<String> getOcspUrls(Certificate cert) {
        ArrayList<String> urls = new ArrayList<String>();
        if(StringUtils.isNotEmpty(this.ocspUrl)) {
            urls.add(this.ocspUrl);
        }
        
        urls.addAll(CertTools.getAuthorityInformationAccessOcspUrls((X509Certificate)cert));
        
        return urls;
    }
    
    private ArrayList<String> getCrlUrl(final Certificate cert) {
        
        ArrayList<String> urls = new ArrayList<String>();
        
        if(StringUtils.isNotEmpty(this.crlUrl)) {
            urls.add(this.crlUrl);
        }
        
        ArrayList<String> crlUrlFromExtension = (ArrayList<String>) CertTools.getCrlDistributionPoints((X509Certificate)cert); 
        urls.addAll(crlUrlFromExtension);
        
        return urls; 
    }
    
    private X509Certificate getCaCert(final Certificate targetCert) {
        if(this.issuerCert != null) {
            return issuerCert;
        }
        
        if(this.caCerts==null) { // no CA specified
            return null;
        }

        for(final X509Certificate cacert : this.caCerts) {
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
