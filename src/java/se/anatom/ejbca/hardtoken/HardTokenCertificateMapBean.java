package se.anatom.ejbca.hardtoken;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;

import org.apache.log4j.Logger;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing certificates placed on a token.
 * Information stored:
 * <pre>
 *  certificatefingerprint 
 *  tokensn 
 * </pre>
 *
 * @version $Id: HardTokenCertificateMapBean.java,v 1.4 2003-02-12 11:23:17 scop Exp $
 */
public abstract class HardTokenCertificateMapBean implements javax.ejb.EntityBean {



    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

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
