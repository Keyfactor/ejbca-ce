package se.anatom.ejbca.hardtoken;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;

import org.apache.log4j.Category;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing certificates placed on a token.
 * Information stored:
 * <pre>
 *  certificatefingerprint 
 *  tokensn 
 * </pre>
 *
 * @version $Id: HardTokenCertificateMapBean.java,v 1.3 2003-02-09 15:02:18 anatom Exp $
 **/

public abstract class HardTokenCertificateMapBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(HardTokenIssuerDataBean.class.getName() );

    protected EntityContext  ctx;  
    
    public abstract String getCertificateFingerprint();
    public abstract void setCertificateFingerprint(String certificatefingerprint);   
        
    public abstract String getTokenSN();
    public abstract void setTokenSN(String tokensn);

     
    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a certificate to hard token relation.
     *
     * @return null
     *
     **/

    public String ejbCreate(String certificatefingerprint, String tokensn) throws CreateException {        
        setCertificateFingerprint(certificatefingerprint);   
        setTokenSN(tokensn);
        
        log.debug("Created HardTokenCertificateMap for token SN: "+ tokensn );
        return certificatefingerprint;
    }

    public void ejbPostCreate(String certificatefingerprint, String tokensn) {
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

