package se.anatom.ejbca.webdist.cainterface;

import java.util.Collection;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.X509CAInfo;
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;

/**
 * A class representing a view of a CA Information view..
 *
 * @version $Id: CAInfoView.java,v 1.1 2003-09-04 09:46:43 herrvendil Exp $
 */
public class CAInfoView implements java.io.Serializable, Cloneable {
    // Public constants.

   public static int NAME           = 0;  
   public static int SUBJECTDN      = 1;   
   public static int SUBJECTALTNAME = 2;
   public static int CATYPE         = 3;
   
   public static int EXPIRETIME     = 5;
   public static int STATUS         = 6;
   public static int DESCRIPTION    = 7;
   
  
    
   public static String[] X509CA_CAINFODATATEXTS = {"NAME","SUBJECTDN","SUBJECTALTNAME","CATYPE","",
                                                    "EXPIRES","STATUS","DESCRIPTION"};
   
   private String[] cainfodata = null;
   private String[] cainfodatatexts = null;
   
   private CAInfo cainfo = null;
    
   
    public CAInfoView(CAInfo cainfo, EjbcaWebBean ejbcawebbean){
      this.cainfo = cainfo;  
        
      if(cainfo instanceof X509CAInfo){
        cainfodatatexts = new String[X509CA_CAINFODATATEXTS.length];
        cainfodata = new String[X509CA_CAINFODATATEXTS.length];  
        
        for(int i=0; i < X509CA_CAINFODATATEXTS.length; i++){
          if(X509CA_CAINFODATATEXTS[i].equals(""))
              cainfodatatexts[i]="&nbsp;";
          else
              cainfodatatexts[i] = ejbcawebbean.getText(X509CA_CAINFODATATEXTS[i]);
        }
        
        cainfodata[SUBJECTDN]  = cainfo.getSubjectDN();
        cainfodata[SUBJECTALTNAME] = ((X509CAInfo) cainfo).getSubjectAltName();
        cainfodata[NAME]       = cainfo.getName();
        cainfodata[CATYPE]     = ejbcawebbean.getText("X509");
        cainfodata[4]          = "&nbsp;"; // blank line
        cainfodata[EXPIRETIME] = ejbcawebbean.printDateTime(cainfo.getExpireTime());
        
        switch(cainfo.getStatus()){
            case SecConst.CA_ACTIVE :
              cainfodata[STATUS]     = ejbcawebbean.getText("ACTIVE");     
              break;
            case SecConst.CA_EXPIRED :
              cainfodata[STATUS]     = ejbcawebbean.getText("EXPIRED");
              break;
            case SecConst.CA_INACTIVE :
              cainfodata[STATUS]     = ejbcawebbean.getText("INACTIVE");
              break;
            case SecConst.CA_REVOKED :
              cainfodata[STATUS]     = ejbcawebbean.getText("CAREVOKED") + ", " + 
                                       ejbcawebbean.getText("REASON") + " :<br>&nbsp;&nbsp;" +
                                       ejbcawebbean.getText(RevokedInfoView.reasontexts[cainfo.getRevokationReason()]);
              break;
            case SecConst.CA_WAITING_CERTIFICATE_RESPONSE :
              cainfodata[STATUS]     = ejbcawebbean.getText("WAITINGFORCERTRESPONSE");
              break;              
        }        
        
        cainfodata[DESCRIPTION] = cainfo.getDescription();
        
      }
   }

   public String[] getCAInfoData(){ return cainfodata;}
   public String[] getCAInfoDataText(){ return cainfodatatexts;} 

   public CAInfo getCAInfo() { return cainfo;}
   public Collection getCertificateChain() { return cainfo.getCertificateChain(); }
   
}
