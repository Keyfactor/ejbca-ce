/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;

/**
 *
 * Marker interface for various certificate implementations 
 *
 */
public interface CertificateImplementation {
    
    /**
     * @return the globally identifyable String represenation for this certificate type.
     */
    String getType();
    
    Class<?> getImplementationClass();
    
    /**
     * 
     * @param certificate a certificate to find the algorithm for
     * @return the signature algorithm for this certificate type
     */
    String getCertificateSignatureAlgorithm(final Certificate certificate);
    
    String getSubjectDn(final Certificate certificate);
    
    String getIssuerDn(final Certificate certificate);
    
    /**
     * Gets Serial number of the certificate.
     * 
     * @param certificate Certificate
     * 
     * @return BigInteger containing the certificate serial number. Can be 0 for CVC certificates with alphanumeric serial numbers if the sequence
     *         does not contain any number characters at all.
     * @throws IllegalArgumentException if null input of certificate type is not handled
     */
     BigInteger getSerialNumber(final Certificate certificate);
     
     /**
      * Gets Serial number of the certificate as a string. For X509 Certificate this means a HEX encoded BigInteger, and for CVC certificate is means
      * the sequence field of the holder reference.
      * <p>
      * For X509 certificates, the value is normalized (uppercase without leading zeros), so there's no need to normalize the returned value.
      * 
      * @param certificate Certificate
      * 
      * @return String to be displayed or used in RoleMember objects
      * @throws IllegalArgumentException if input is null or certificate type is not implemented
      */
      String getSerialNumberAsString(final Certificate certificate);
      
      /**
       * Gets the signature value (the raw signature bits) from the certificate. For an X509 certificate this is the ASN.1 definition which is:
       * signature BIT STRING
       * 
       * @param certificate Certificate
       * 
       * @return byte[] containing the certificate signature bits, if cert is null a byte[] of size 0 is returned.
       */
       byte[] getSignature(final Certificate certificate);
       
       Date getNotAfter(final Certificate certificate);
       
       Date getNotBefore(final Certificate certificate);
       
       /**
        * 
        * @param provider a provider name 
        * @param cert a byte array containing an encoded certificate
        * @return a decoded X509Certificate
        * @throws CertificateParsingException if the byte array wasn't valid, or contained a certificate other than an X509 Certificate. 
        */
        Certificate parseCertificate(final String provider, final byte[] cert) throws CertificateParsingException;
        
        /**
         * Checks if a certificate is a CA certificate according to BasicConstraints (X.509), or role (CVC). If there is no basic constraints extension on
         * a X.509 certificate, false is returned.
         * 
         * @param certificate the certificate that shall be checked.
         * 
         * @return boolean true if the certificate belongs to a CA.
         */
         boolean isCA(final Certificate certificate);
         
         /**
          * Checks that the given date is within the certificate's validity period. In other words, this determines whether the certificate would be valid
          * at the given date/time.
          * 
          * This utility class is only a helper to get the same behavior as the standard java.security.cert API regardless if using X.509 or CV
          * Certificate.
          * 
          * @param certificate certificate to verify, if null the method returns immediately, null does not have a validity to check.
          * @param date the Date to check against to see if this certificate is valid at that date/time.
          * @throws NoSuchFieldException
          * @throws CertificateExpiredException - if the certificate has expired with respect to the date supplied.
          * @throws CertificateNotYetValidException - if the certificate is not yet valid with respect to the date supplied.
          */
          void checkValidity(final Certificate certificate, final Date date) throws CertificateExpiredException, CertificateNotYetValidException;
          
          /**
           * Dumps a certificate (cvc or x.509) to string format, suitable for manual inspection/debugging.
           * 
           * @param certificate Certificate
           * 
           * @return String with cvc or asn.1 dump.
           */
           String dumpCertificateAsString(final Certificate certificate);
          
}
