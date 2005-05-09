/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.anatom.ejbca.webdist.hardtokeninterface;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.authorization.AdminGroup;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.hardtoken.HardTokenData;
import se.anatom.ejbca.hardtoken.HardTokenIssuer;
import se.anatom.ejbca.hardtoken.HardTokenIssuerData;
import se.anatom.ejbca.hardtoken.HardTokenIssuerDoesntExistsException;
import se.anatom.ejbca.hardtoken.HardTokenIssuerExistsException;
import se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionLocal;
import se.anatom.ejbca.hardtoken.IHardTokenBatchJobSessionLocalHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocalHome;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocal;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.IUserAdminSessionLocalHome;
import se.anatom.ejbca.util.ServiceLocator;
import se.anatom.ejbca.webdist.rainterface.RAInterfaceBean;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;
import se.anatom.ejbca.webdist.webconfiguration.InformationMemory;

/**
 * A java bean handling the interface between EJBCA hard token module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: LogInterfaceBean.java,v 1.13 2002/08/28 12:22:25 herrvendil Exp $
 */
public class HardTokenInterfaceBean implements java.io.Serializable {

	/** Creates new LogInterfaceBean */
    public HardTokenInterfaceBean(){
    }
    // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{

      if(!initialized){
        admin           = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
            
        final ServiceLocator locator = ServiceLocator.getInstance();
        IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome) locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
        hardtokensession = hardtokensessionhome.create();

        IHardTokenBatchJobSessionLocalHome  hardtokenbatchsessionhome = (IHardTokenBatchJobSessionLocalHome) locator.getLocalHome(IHardTokenBatchJobSessionLocalHome.COMP_NAME);
        hardtokenbatchsession = hardtokenbatchsessionhome.create();
        
		IAuthorizationSessionLocalHome  authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
		IAuthorizationSessionLocal authorizationsession = authorizationsessionhome.create();

		IUserAdminSessionLocalHome adminsessionhome = (IUserAdminSessionLocalHome) locator.getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
		IUserAdminSessionLocal useradminsession = adminsessionhome.create();

		ICertificateStoreSessionLocalHome certificatestorehome = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
		ICertificateStoreSessionLocal certificatesession = certificatestorehome.create();

        IKeyRecoverySessionLocalHome keyrecoverysessionhome = (IKeyRecoverySessionLocalHome) locator.getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
        keyrecoverysession = keyrecoverysessionhome.create();
		
        initialized=true;
        
        this.informationmemory = ejbcawebbean.getInformationMemory();
                      
        this.hardtokenprofiledatahandler = new HardTokenProfileDataHandler(admin, hardtokensession, certificatesession, authorizationsession , useradminsession, informationmemory);
		
      }
    }
    
    /* Returns the first found hard token for the given username. */
    public HardTokenView getHardTokenViewWithUsername(String username) {
      this.result=null;

      Collection res = hardtokensession.getHardTokens(admin, username);
      Iterator iter = res.iterator();
      if(res.size() > 0) {
        this.result = new HardTokenView[res.size()];
        for(int i=0;iter.hasNext();i++) {
          this.result[i]=new HardTokenView((HardTokenData) iter.next());
        }
        
        if(this.result!= null && this.result.length > 0) {
            return this.result[0];
        }
        
      }   
      return null;        
    }
    
    public HardTokenView getHardTokenViewWithIndex(String username, int index) {
        HardTokenView returnval=null;
        
        if(result == null)
            getHardTokenViewWithUsername(username);
        
        if(result!=null)
            if(index < result.length)
                returnval=result[index];
        
        return returnval;
    }
    
    public int getHardTokensInCache() {
        int returnval = 0;
        if(result!=null)
            returnval = result.length;
        
        return returnval;
    }
    
    public HardTokenView getHardTokenView(String tokensn) {
        HardTokenView  returnval = null;
        this.result=null;
        HardTokenData token =  hardtokensession.getHardToken(admin, tokensn);
        if(token != null)
            returnval = new  HardTokenView(token);
        
        return returnval;
    }
    
    public Collection getHardTokenIssuerDatas() {
        return hardtokensession.getHardTokenIssuerDatas(admin);
    }
    
    public TreeMap getHardTokenIssuers() {
        return hardtokensession.getHardTokenIssuers(admin);
    }
    
    public String[] getHardTokenIssuerAliases() {
        return (String[]) hardtokensession.getHardTokenIssuers(admin).keySet().toArray(new String[0]);
    }
    
    /** Returns the alias from id. */
    public String getHardTokenIssuerAlias(int id) {
        return hardtokensession.getHardTokenIssuerAlias(admin, id);
    }
    
    public int getHardTokenIssuerId(String alias) {
        return hardtokensession.getHardTokenIssuerId(admin, alias);
    }
    
    public HardTokenIssuerData getHardTokenIssuerData(String alias) {
        return hardtokensession.getHardTokenIssuerData(admin, alias);
    }
    
    public HardTokenIssuerData getHardTokenIssuerData(int id) {
        return hardtokensession.getHardTokenIssuerData(admin, id);
    }
    
    public void addHardTokenIssuer(String alias, int admingroupid) throws HardTokenIssuerExistsException {
        Iterator iter = this.informationmemory.getHardTokenIssuingAdminGroups().iterator();
        while(iter.hasNext()){
            if(((AdminGroup) iter.next()).getAdminGroupId() == admingroupid){
                if(!hardtokensession.addHardTokenIssuer(admin, alias, admingroupid, new HardTokenIssuer()))
                    throw new HardTokenIssuerExistsException();
                informationmemory.hardTokenDataEdited();      		
            }
        }      
    }
    
    public void changeHardTokenIssuer(String alias, HardTokenIssuer hardtokenissuer) throws HardTokenIssuerDoesntExistsException {
        if(informationmemory.authorizedToHardTokenIssuer(alias)){	          	
            if(!hardtokensession.changeHardTokenIssuer(admin, alias, hardtokenissuer))
                throw new HardTokenIssuerDoesntExistsException();
            informationmemory.hardTokenDataEdited();
        }
    }
    
    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeHardTokenIssuer(String alias) {		
        boolean issuerused = false;
        if(informationmemory.authorizedToHardTokenIssuer(alias)){
            int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);
            // Check if any users or authorization rule use the profile.
            
            issuerused = hardtokenbatchsession.checkForHardTokenIssuerId(admin, issuerid);
            
            if(!issuerused){
                hardtokensession.removeHardTokenIssuer(admin, alias);
                informationmemory.hardTokenDataEdited();
            }		
        } 
        return !issuerused;	
    }
    
    public void renameHardTokenIssuer(String oldalias, String newalias, int newadmingroupid) throws HardTokenIssuerExistsException {
        if(informationmemory.authorizedToHardTokenIssuer(oldalias)){	        
            if(!hardtokensession.renameHardTokenIssuer(admin, oldalias, newalias, newadmingroupid))
                throw new HardTokenIssuerExistsException();
            
            informationmemory.hardTokenDataEdited();
        }   
    }
    
    public void cloneHardTokenIssuer(String oldalias, String newalias, int newadmingroupid) throws HardTokenIssuerExistsException {
        if(informationmemory.authorizedToHardTokenIssuer(oldalias)){    	        
            if(!hardtokensession.cloneHardTokenIssuer(admin, oldalias, newalias, newadmingroupid))
                throw new HardTokenIssuerExistsException();
            
            informationmemory.hardTokenDataEdited();
        }
    }

/**
 * Method that checks if a token is key recoverable and also check if the administrator is authorized to the action.
 * @param tokensn
 * @param rabean
 * @return
 */
    
    public boolean isTokenKeyRecoverable(String tokensn, String username, RAInterfaceBean rabean) throws Exception{
      boolean retval = false;	
      X509Certificate keyRecCert = null;            
      
      Collection result = hardtokensession.findCertificatesInHardToken(admin, tokensn);      
      Iterator iter = result.iterator();
      while(iter.hasNext()){      	
      	X509Certificate cert = (X509Certificate) iter.next();
      	if(keyrecoverysession.existsKeys(admin,cert)){      
      		keyRecCert = cert;
      	}
      }
            
      if(keyRecCert != null){
       retval = rabean.keyRecoveryPossible(keyRecCert,username); 
      }
      
      return retval;	
    }
    
    public void markTokenForKeyRecovery(String tokensn,String username, RAInterfaceBean rabean) throws Exception{                   
        Collection result = hardtokensession.findCertificatesInHardToken(admin, tokensn);
        Iterator iter = result.iterator();
        while(iter.hasNext()){
        	X509Certificate cert = (X509Certificate) iter.next();
        	if(keyrecoverysession.existsKeys(admin,cert)){
        		rabean.markForRecovery(username,cert);        		
        	}
        }              
    }
    
	
	public HardTokenProfileDataHandler getHardTokenProfileDataHandler() {	
		return hardtokenprofiledatahandler;
	}    
    // Private fields.
    private IHardTokenSessionLocal                hardtokensession;
    private IKeyRecoverySessionLocal              keyrecoverysession;
    private IHardTokenBatchJobSessionLocal  hardtokenbatchsession;        
    private Admin                                          admin;
    private InformationMemory                      informationmemory;
    private boolean                                       initialized=false;
    private HardTokenView[]                          result;
    private HardTokenProfileDataHandler         hardtokenprofiledatahandler;
    
}
