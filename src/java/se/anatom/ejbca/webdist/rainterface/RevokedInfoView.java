/*
 * RevokedInfoView.java
 *
 * Created on den 1 maj 2002, 07:55
 */

package se.anatom.ejbca.webdist.rainterface;

import java.util.Date;
import java.util.Vector;
import java.math.BigInteger;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;


/**
 *
 * @author  Philip Vendil
 */
public class RevokedInfoView {
    
    // Public constants.
    public static final int UNUSED                = 0x0001;    
    public static final int KEYCOMPROMISE         = 0x0002;
    public static final int CACOMPROMISE          = 0x0004;
    public static final int AFFILIATIONCHANGED    = 0x0008;
    public static final int SUPERSEDED            = 0x0010; 
    public static final int CESSATIONOFOPERATION  = 0x0020;    
    public static final int CERTIFICATEHOLD       = 0x0040;   

        
    /** Creates a new instance of RevokedInfoView */
    public RevokedInfoView(RevokedCertInfo revokedcertinfo) {
      this.revokedcertinfo=revokedcertinfo;
    }
    
    // Public methods.
    public String getCertificateSerialNumberAsString(){
      return this.revokedcertinfo.getUserCertificate().toString(16); 
    }
    
    public BigInteger getCertificateSerialNumber(){
      return this.revokedcertinfo.getUserCertificate();
    }
    
    public Date getRevocationDate(){
      return this.revokedcertinfo.getRevocationDate();
    }
    
    public String[] getRevokationReasons(){
      String[] dummy = {""};
      Vector reasons = new Vector();
        for(int i=0; i < reasonmasks.length; i++){
           if((this.revokedcertinfo.getReason() & reasonmasks[i]) > 0){
             // Add this reason.
               reasons.addElement(reasontexts[i]);
           }
        }
        if(reasons.size()==0){
          reasons.addElement("UNKNOWNREASON");            
        }
      
      return (String[]) reasons.toArray(dummy);  
    }
        
    // Private constants.

    private static final int[] reasonmasks = {UNUSED,KEYCOMPROMISE,CACOMPROMISE,
                                             AFFILIATIONCHANGED,SUPERSEDED,CESSATIONOFOPERATION,
                                             CERTIFICATEHOLD};
    private static final String[] reasontexts = {"UNUSED","KEYCOMPROMISE","CACOMPROMISE",
                                                  "AFFILIATIONCHANGED","SUPERSEDED",
                                                  "CESSATIONOFOPERATION","CERTIFICATEHOLD"};
    
    // Private fields.
    private RevokedCertInfo revokedcertinfo;
    
}
