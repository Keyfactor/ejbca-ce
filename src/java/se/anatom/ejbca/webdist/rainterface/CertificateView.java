package se.anatom.ejbca.webdist.rainterface;

import java.util.Date;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;


/**
 * A class transforming X509 certificate data inte more readable form used
 * by JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: CertificateView.java,v 1.7 2003-02-25 13:54:02 scop Exp $
 */
public class CertificateView {

   public static final int DIGITALSIGNATURE = CertificateProfile.DIGITALSIGNATURE;
   public static final int NONREPUDIATION   = CertificateProfile.NONREPUDIATION;
   /** @deprecated use NONREPUDIATION instead */
   public static final int NONREPUDATION    = NONREPUDIATION;
   public static final int KEYENCIPHERMENT  = CertificateProfile.KEYENCIPHERMENT;
   public static final int DATAENCIPHERMENT = CertificateProfile.DATAENCIPHERMENT;
   public static final int KEYAGREEMENT     = CertificateProfile.KEYAGREEMENT;
   public static final int KEYCERTSIGN      = CertificateProfile.KEYCERTSIGN;
   public static final int CRLSIGN          = CertificateProfile.CRLSIGN;
   public static final int ENCIPHERONLY     = CertificateProfile.ENCIPHERONLY;
   public static final int DECIPHERONLY     = CertificateProfile.DECIPHERONLY;


    /** Creates a new instance of CertificateView */
    public CertificateView(X509Certificate certificate, RevokedInfoView revokedinfo, String username) {
      this.certificate=certificate;
      this.revokedinfo= revokedinfo;
      this.username=username;

      subjectdnfieldextractor = new DNFieldExtractor(certificate.getSubjectDN().toString(), DNFieldExtractor.TYPE_SUBJECTDN);
      issuerdnfieldextractor  = new DNFieldExtractor(certificate.getIssuerDN().toString(), DNFieldExtractor.TYPE_SUBJECTDN);
    }


    // Public methods
    /** Method that returns the version number of the X509 certificate. */
    public String getVersion() {
      return Integer.toString(certificate.getVersion());
    }

    public String getType() {
      return "X509";
    }

    public String getSerialNumber() {
      return certificate.getSerialNumber().toString(16).toUpperCase();
    }

    public BigInteger getSerialNumberBigInt() {
      return certificate.getSerialNumber();
    }

    public String getIssuerDN() {
      return certificate.getIssuerDN().toString();
    }

    public String getIssuerDNField(int field, int number) {
      return issuerdnfieldextractor.getField(field, number);
    }

    public String getSubjectDN() {
      return certificate.getSubjectDN().toString();
    }

    public String getSubjectDNField(int field, int number) {
      return subjectdnfieldextractor.getField(field, number);
    }

    public Date getValidFrom() {
      return certificate.getNotBefore();
    }

    public Date getValidTo() {
      return certificate.getNotAfter();
    }

    public boolean checkValidity(){
      boolean valid = true;
      try{
        certificate.checkValidity();
      }
      catch( CertificateExpiredException e){
        valid=false;
      }
      catch(CertificateNotYetValidException e){
         valid=false;
      }

      return valid;
    }

    public boolean checkValidity(Date date)  {
      boolean valid = true;
      try{
        certificate.checkValidity(date);
      }
      catch( CertificateExpiredException e){
        valid=false;
      }
      catch(CertificateNotYetValidException e){
         valid=false;
      }

      return valid;
    }

    public String getPublicKeyAlgorithm(){
      return certificate.getPublicKey().getAlgorithm();
    }

    public String getPublicKeyLength(){
      String keylength = null;
      if( certificate.getPublicKey() instanceof RSAPublicKey){
        keylength = "" + ((RSAPublicKey)certificate.getPublicKey()).getModulus().bitLength();
      }
      return keylength;
    }

    public String getSignatureAlgoritm() {
      return certificate.getSigAlgName();
    }

    /** Method that returns if key is allowed for given usage. Usage must be one of this class key usage constants. */
    public boolean getKeyUsage(int usage) {
      boolean returnval = false;
      if(certificate.getKeyUsage() != null)
        returnval= certificate.getKeyUsage()[usage];

      return returnval;
    }

    public boolean[] getAllKeyUsage(){
      return certificate.getKeyUsage();
    }

    public String getBasicConstraints() {
      return Integer.toString(certificate.getBasicConstraints());
    }

    public String getSignature() {
      return (new java.math.BigInteger(certificate.getSignature())).toString(16);
    }

    public String getSHA1Fingerprint(){
      String returnval = "";
      try {
         byte[] res = CertTools.generateSHA1Fingerprint(certificate.getEncoded());
         returnval = (Hex.encode(res)).toUpperCase();
      } catch (CertificateEncodingException cee) {
      }
      return  returnval;
    }

    public String getMD5Fingerprint(){
      String returnval = "";
      try {
         byte[] res = CertTools.generateMD5Fingerprint(certificate.getEncoded());
         returnval = (Hex.encode(res)).toUpperCase();
      } catch (CertificateEncodingException cee) {
      }
      return  returnval;
    }


    public boolean isRevoked(){
      return revokedinfo != null;
    }

    public String[] getRevokationReasons(){
      String[] returnval = null;
      if(revokedinfo != null)
        returnval = revokedinfo.getRevokationReasons();
      return returnval;
    }

    public Date getRevokationDate(){
      Date returnval = null;
      if(revokedinfo != null)
        returnval = revokedinfo.getRevocationDate();
      return returnval;
    }

    public String getUsername(){
      return this.username;
    }

    public X509Certificate getCertificate(){
      return certificate;
    }

    // Private fields
    private X509Certificate  certificate;
    private DNFieldExtractor subjectdnfieldextractor, issuerdnfieldextractor;
    private RevokedInfoView  revokedinfo;
    private String           username;
}
