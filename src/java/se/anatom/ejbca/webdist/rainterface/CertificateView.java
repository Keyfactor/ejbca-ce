/*
 * CertificateView.java
 *
 * Created on den 1 maj 2002, 06:31
 */

package se.anatom.ejbca.webdist.rainterface;

import java.util.Date;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateEncodingException; 
import java.security.interfaces.RSAPublicKey;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;


/**
 * A class transorming X509 certificate data inte more readable form userd by JSP pages.
 *
 * @author  Philip Vendil
 */
public class CertificateView {
    
   public static final int DIGITALSIGNATURE = 0;
   public static final int NONREPUDATION    = 1;
   public static final int KEYENCIPHERMENT  = 2;
   public static final int DATAENCIPHERMENT = 3;
   public static final int KEYAGREEMENT     = 4;
   public static final int KEYCERTSIGN      = 5;
   public static final int CRLSIGN          = 6;
   public static final int ENCIPHERONLY     = 7;
   public static final int DECIPHERONLY     = 8;
   
        
    /** Creates a new instance of CertificateView */
    public CertificateView(X509Certificate certificate, RevokedInfoView revokedinfo) {
      this.certificate=certificate;
      this.revokedinfo= revokedinfo;  
      
      subjectdnfieldextractor = new DNFieldExtractor(certificate.getSubjectDN().toString()); 
      issuerdnfieldextractor  = new DNFieldExtractor(certificate.getIssuerDN().toString());  
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
    
    public String getIssuerDN() {
      return certificate.getIssuerDN().toString();  
    }
    
    public String getIssuerDNField(String field) { 
      return issuerdnfieldextractor.getField(field);  
    }  
    
    public String getSubjectDN() {
      return certificate.getSubjectDN().toString();  
    }
    
    public String getSubjectDNField(String field) {
      return subjectdnfieldextractor.getField(field);  
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
    
    // Private fields
    private X509Certificate  certificate;    
    private DNFieldExtractor subjectdnfieldextractor, issuerdnfieldextractor;
    private RevokedInfoView  revokedinfo;
}
