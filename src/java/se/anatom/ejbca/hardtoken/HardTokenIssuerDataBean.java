package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import java.util.HashMap;
import java.math.BigInteger;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token issuer in the ra.
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  alias (of the hard token issuer)
 *  certificatesn (Certificate SN of the hard token issuer)
 *  certificateissuersn (The SN of the certificate issuing the hard toke issuers certificate.) 
 *  hardtokenissuer (Data saved concerning the hard token issuer)
 * </pre>
 *
 * @version $Id: HardTokenIssuerDataBean.java,v 1.7 2003-09-03 12:47:24 herrvendil Exp $
 **/

public abstract class HardTokenIssuerDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getAlias();
    public abstract void setAlias(String alias);
    
    public abstract String getCertificateSN();
    public abstract void setCertificateSN(String certificatesn);
    
    public abstract String getCertIssuerDN();    
    public abstract void setCertIssuerDN(String certissuerdn);  

    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
    public BigInteger getCertSN(){ return new BigInteger(getCertificateSN(),16); }
    
    public void setCertSN(BigInteger certificatesn){ setCertificateSN(certificatesn.toString(16)); } 

   
    /** 
     * Method that returns the hard token issuer data and updates it if nessesary.
     */    
    
    public HardTokenIssuer getHardTokenIssuer(){
      HardTokenIssuer returnval = new HardTokenIssuer();
      returnval.loadData((Object) getData());
      return returnval;              
    }
    
    /** 
     * Method that saves the hard token issuer data to database.
     */    
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer){
       setData((HashMap) hardtokenissuer.saveData());          
    }
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String alias, BigInteger certificatesn, String certissuerdn,  HardTokenIssuer issuerdata) throws CreateException {
        setId(id);
        setAlias(alias);
        setCertificateSN(certificatesn.toString(16));   
        setCertIssuerDN(certissuerdn);     
        setHardTokenIssuer(issuerdata);
        
        log.debug("Created Hard Token Issuer "+ alias );
        return id;
    }

    public void ejbPostCreate(Integer id, String alias, BigInteger certificatesn, String certissuerdn,  HardTokenIssuer issuerdata) {
        // Do nothing. Required.
    }
}
