package se.anatom.ejbca.hardtoken;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.HashMap;
import java.math.BigInteger;
import org.apache.log4j.*;
import se.anatom.ejbca.hardtoken.HardTokenIssuer;

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
 * @version $Id: HardTokenIssuerDataBean.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 **/

public abstract class HardTokenIssuerDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(HardTokenIssuerDataBean.class.getName() );

    protected EntityContext  ctx;
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

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

