/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.pub;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.ObjectNotFoundException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.StringTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * A class used as an interface between Apply jsp pages and ejbca functions.
 *
 * @version $Id$
 */
public class ApplyBean implements Serializable {
    /**
	 * Version number for serialization
	 */
	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(ApplyBean.class);
	
    private boolean initialized;
    private AuthenticationToken administrator;
    private String username = "";
    private EndEntityInformation endEntityInformation = null;
    private String browser = "unknown";
    /** Is set to true by setUserOk if user exists and password is correct */
    private boolean userOk = false;
	
	private EjbLocalHelper ejbLocalHelper;
	
	/**
     * Creates a new instance of CaInterfaceBean
     */
    public ApplyBean() {
    }

    // Public methods
    public void initialize(HttpServletRequest request)
        throws Exception {
        if (!initialized) {
            administrator = new AlwaysAllowLocalAuthenticationToken(new PublicWebPrincipal(request.getRemoteAddr()));
            ejbLocalHelper = new EjbLocalHelper();
            browser = detectBrowser(request);
            initialized = true;
        }
    }

    /**
     * Method that returns a users tokentype defined in SecConst, if 0 is returned user couldn't be
     * found i database.
     *
     * @param username the user whose tokentype should be returned
     *
     * @return caid of user.
     *
     * @see org.ejbca.core.model.SecConst
     */
    public int getTokenType(String username) throws Exception {
        int returnval = 0;

		if(!username.equals(this.username) || this.endEntityInformation == null){        
			this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
		}
		
        if (endEntityInformation != null) {
            returnval = endEntityInformation.getTokenType();
        }
		this.username = username;
		if (log.isTraceEnabled()) {
			log.trace("<getTokenType(" + username + ") --> " + returnval);
		}
        return returnval;
    }

    /**
     * Method that returns the CAId of the CA the user was registered with, if 0 is returned user couldn't be
     * found i database.
     *
     * @param username the user whose caid should be returned
     *
     * @return caid
     */
	public int getCAId(String username) throws Exception {
		int returnval = 0;		

		if(!username.equals(this.username) || this.endEntityInformation == null){        
			this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
		}
		
		if (endEntityInformation != null) {
			returnval = endEntityInformation.getCAId();
		}
		this.username = username;
		if (log.isTraceEnabled()) {
			log.trace("<getCAId(" + username + ") --> " + returnval);
		}
		return returnval;
	}


    /**
     * Method that returns a bitlengths available for the user. Returns null if user couldn't be
     * found in database.
     *
     * @param username user whose bit lengts are requested.
     *
     * @return array of available bit lengths
     */
    public int[] availableBitLengths(String username) throws Exception {
        int[] returnval = null;        

        if(!username.equals(this.username) || this.endEntityInformation == null){        
        	this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
        }  

        if (endEntityInformation != null) {
            int certprofile = endEntityInformation.getCertificateProfileId();

            if (certprofile != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                CertificateProfile p = ejbLocalHelper.getCertificateProfileSession().getCertificateProfile(certprofile);
                returnval = p.getAvailableBitLengths();
            }
        }
        this.username = username;

        if (log.isDebugEnabled()) {
        	String retdebug = "";
        	if (returnval != null) {
        		for (int i=0;i<returnval.length;i++) {
        			if (StringUtils.isNotEmpty(retdebug)) {
        				retdebug += ",";
        			}
            		retdebug += returnval[i];        			
        		}
        	}
        	if (log.isTraceEnabled()) {
        		log.trace("<availableBitLengths(" + username + ") --> " + retdebug);
        	}
        }
        return returnval;
    }

    /**
     * Method that returns the avialable certificate profiles for the end entity profile 
     * a user is registered with. Returns null if user couldn't be found in database.
     *
     * @param username user whose certificate profiles are requested.
     *
     * @return array of available certificate profile names
     */
    public String[] availableCertificateProfiles(String username) throws Exception {
        String[] returnval = null;        

        if(!username.equals(this.username) || this.endEntityInformation == null){        
        	this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
        }  

        if (endEntityInformation != null) {
            EndEntityProfile eprof = ejbLocalHelper.getEndEntityProfileSession().getEndEntityProfile(endEntityInformation.getEndEntityProfileId());
            Collection<String> c = eprof.getAvailableCertificateProfileIds();
            if (!c.isEmpty()) {
            	ArrayList<String> names = new ArrayList<String>();
                for (Iterator<String> i = c.iterator(); i.hasNext(); ) {
                	int id = Integer.valueOf(i.next());
                    String name = ejbLocalHelper.getCertificateProfileSession().getCertificateProfileName(id);
                	names.add(name);
                }
                returnval = (String[])names.toArray(new String[names.size()]);            	
            }
        }
        this.username = username;

        if (log.isDebugEnabled()) {
        	String retdebug = "";
        	if (returnval != null) {
        		for (int i=0;i<returnval.length;i++) {
        			if (StringUtils.isNotEmpty(retdebug)) {
        				retdebug += ",";
        			}
            		retdebug += returnval[i];        			
        		}
        	}
        	if (log.isTraceEnabled()) {
        		log.trace("<availableCertificateProfiles(" + username + ") --> " + retdebug);
        	}
        }
        return returnval;
    }

    /**
     * Method that returns the certificate profile registered for the end entity. 
     * Returns null if user couldn't be found in database.
     *
     * @param username user whose certificate profile is requested.
     *
     * @return certificate profile name
     */
    public String getUserCertificateProfile(String username) throws Exception {
        String returnval = null;        

        if(!username.equals(this.username) || this.endEntityInformation == null){        
        	this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
        }  

        if (endEntityInformation != null) {
            returnval = ejbLocalHelper.getCertificateProfileSession().getCertificateProfileName(endEntityInformation.getCertificateProfileId());
        }
        this.username = username;

        if (log.isTraceEnabled()) {
        	log.trace("<getUserCertificateProfile(" + username + ") --> " + returnval);
        }
        return returnval;
    }

    /**
     * Method that returns if the user exists and password matches.
     *
     * @param username user whose authentication should be checked.
     *
     * @return true if user exists and pwd is ok, false otherwise
     */
    public void setUserOk(String username, String password) throws Exception {
        if(!username.equals(this.username) || this.endEntityInformation == null){
            this.userOk = ejbLocalHelper.getEndEntityManagementSession().verifyPassword(administrator, username, password);
        }
        if (log.isTraceEnabled()) {
            log.trace("<userOk(" + username + ") --> " + this.userOk);
        }
    }

    /**
     * Returns if the user exists and password matches. Must be initialized by call to setUserOk(username, password)
     *
     * @return true if user exists and pwd is ok, false otherwise
     */
    public boolean getUserOk() {
        return this.userOk;
    }
    
    /**
     * Detects the browser type from the User-Agent HTTP header and returns it.
     * @return Either "netscape", "explorer" or "unknown"
     */
    private String detectBrowser(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null) {
            final boolean isGecko = userAgent.contains("Gecko");
            final boolean isIE = userAgent.contains("MSIE");
            final boolean isNewIE = userAgent.contains("Trident"); // IE11
            
            if (isIE && !isGecko) return "explorer";
            if (isNewIE) return "explorer";
            if (isGecko && !isNewIE) return "netscape";
            /*
             * TODO: IE 11.0 will emulate Firefox in some aspects and implement some HTML5 stuff
             * (<keygen> is standardized in HTML5). When it has been released we should try it out.
             * 
             * See: http://msdn.microsoft.com/en-us/library/ie/bg182625%28v=vs.85%29.aspx
             */
        }
        return "unknown";
    }
    
    /**
     * Returns the detected browser type.
     * @see detectBrowser(Request)
     * @return Either "netscape", "explorer" or "unknown"
     */
    public String getBrowser() {
        return browser;
    }

    
    //--------------------------------------------------------------
    // Convenience methods used from JSTL.
    // In JSTL, there is no practical way of calling regular functions,
    // but accessing "properties" of objects (get-methods without arguments)
    // is easy. Since most methods in ApplyBean take a "username" argument,
    // we give the JSP page a way to set the username beforehand and then
    // access the other methods like properties.
    
    private String defaultUsername = "";
    
    /**
     * Sets the default user name. Some methods in this class come in two versions,
     * one that takes a String username and one without arguments. The version without
     * argument uses the default user name set by this method. 
     * 
     * @param newUsername The new default user name
     */
    public void setDefaultUsername(String newUsername) {
    	defaultUsername = newUsername;
    }

    /**
     * Returns the token type for the default user.
     * @see #setDefaultUsername(String) 
     * @see #getTokenType(String)
     * @return the token type for the default user.
     * @throws Exception if an error occurs
     */
    public int getTokenType() throws Exception {
    	return getTokenType(defaultUsername);
    }

    /**
     * Returns the CA identity for the default user.
     * @see #setDefaultUsername(String) 
     * @see #getCAId(String)
     * @return the CA Id for the default user.
     * @throws Exception if an error occurs
     */
	public int getCAId() throws Exception {
    	return getCAId(defaultUsername);
    }

    /**
     * Returns the encryption key lengths available to the default user.
     * @see #setDefaultUsername(String) 
     * @see #availableBitLengths(String)
     * @return the bit lengths available to the default user.
     * @throws Exception if an error occurs
     */
	public int[] getAvailableBitLengths() throws Exception {
		return availableBitLengths(defaultUsername);
	}
	
	/**
     * Returns the smallest available keylength.
     * @see #getAvailableBitLengths() 
     * @return the minimum key length, or Integer.MAX_VALUE if there are no keylengths available.
     */
    public int getMinimumAvailableKeyLength() throws Exception {
        int minimum = Integer.MAX_VALUE;
        int[] keylengths = getAvailableBitLengths();
        if (keylengths != null) {
            for (int keylength : keylengths) {
                if (keylength < minimum) {
                    minimum = keylength;
                }
            }
        }
        return minimum;
    }
    
    /**
     * Checks if there's more than one key length to choose from
     * @return true if there's more than one key length, or if no available key lengths could be found.
     * @throws Exception
     */
    public int getNumberOfLengthsAvailable() throws Exception {
        int[] keylengths = getAvailableBitLengths();
        return keylengths == null ? 0 : keylengths.length; 
    }
    
    public int getAvailableTokenKeySpecsSize() throws IllegalStateException, AuthorizationDeniedException {
        return getAvailableTokenKeySpecs().length;
    }
	public String[] getAvailableTokenKeySpecs() throws IllegalStateException, AuthorizationDeniedException {
	    return getAvailableTokenKeySpecs(defaultUsername);
	}
    public String[] getAvailableTokenKeySpecs(String username) throws IllegalStateException, AuthorizationDeniedException {
        final List<String> ret = new ArrayList<>();
        if(!username.equals(this.username) || this.endEntityInformation == null){        
            this.endEntityInformation = ejbLocalHelper.getEndEntityAccessSession().findUser(administrator, username);
        }
        this.username = username;
        CertificateProfile certificateProfile = null;
        if (endEntityInformation != null) {
            final int certprofile = endEntityInformation.getCertificateProfileId();
            if (certprofile != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                certificateProfile = ejbLocalHelper.getCertificateProfileSession().getCertificateProfile(certprofile);
            } else {
                throw new IllegalStateException("End entity must have a certificate profile.");
            }
        }
        final List<String> availableKeyAlgorithms = certificateProfile.getAvailableKeyAlgorithmsAsList();
        final List<Integer> availableBitLengths = certificateProfile.getAvailableBitLengthsAsList();
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
            for (final int availableBitLength : availableBitLengths) {
                if (availableBitLength==1024) {
                    ret.add(AlgorithmConstants.KEYALGORITHM_DSA + "_" + availableBitLength + ";" + AlgorithmConstants.KEYALGORITHM_DSA + " " + availableBitLength + " bits");
                }
            }
        }
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
            for (final int availableBitLength : availableBitLengths) {
                if (availableBitLength>=1024) {
                    ret.add(AlgorithmConstants.KEYALGORITHM_RSA + "_" + availableBitLength + ";" + AlgorithmConstants.KEYALGORITHM_RSA + " " + availableBitLength + " bits");
                }
            }
        }
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            final Set<String> ecChoices = new HashSet<>();
            final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap(false);
            if (certificateProfile.getAvailableEcCurvesAsList().contains(CertificateProfile.ANY_EC_CURVE)) {
                final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
                for (final String ecNamedCurve : keys) {
                    if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                        continue;
                    }
                    final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                    if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                        ecChoices.add(ecNamedCurve);
                    }
                }
            }
            ecChoices.addAll(certificateProfile.getAvailableEcCurvesAsList());
            ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
            final List<String> ecChoicesList = new ArrayList<>(ecChoices);
            Collections.sort(ecChoicesList);
            for (final String ecNamedCurve : ecChoicesList) {
                ret.add(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve + ";"+AlgorithmConstants.KEYALGORITHM_ECDSA + " " +
                        StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(ecNamedCurve)));
            }
        }
        for (final String algName : CesecoreConfiguration.getExtraAlgs()) {
            if (availableKeyAlgorithms.contains(CesecoreConfiguration.getExtraAlgTitle(algName))) {
                for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                    final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                    final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                    if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                        ret.add(CesecoreConfiguration.getExtraAlgTitle(algName) + "_" + name + ";" + CesecoreConfiguration.getExtraAlgSubAlgTitle(algName, subAlg));
                    } else {
                        if (log.isTraceEnabled()) {
                            log.trace("Excluding " + name + " from enrollment options since bit length " + bitLength + " is not available.");
                        }
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            for (final String availableTokenKeySpec : ret) {
                if (sb.length()>0) {
                    sb.append(", ");
                }
                sb.append(availableTokenKeySpec);
            }
            log.debug("<availableBitLengths(" + username + ") --> " + sb.toString());
        }
        return ret.toArray(new String[ret.size()]);
    }

    /**
     * Returns the default encryption key lengths.
     * @see #availableBitLengths(String)
     * @return the default bit lengths available.
     * @throws Exception if an error occurs
     */
	public int[] getDefaultBitLengths() throws Exception {
		return SecConst.DEFAULT_KEY_LENGTHS;
	}
	
    /**
     * Returns the certificate profiles available to the default user.
     * @see #setDefaultUsername(String) 
     * @see #availableCertificateProfiles(String)
     * @return the certificate profile names available to the default user.
     * @throws Exception if an error occurs
     */
	public String[] getAvailableCertificateProfiles() throws Exception {
		return availableCertificateProfiles(defaultUsername);
	}
	
	/**
     * Returns true if a list of certificate profiles should be shown to the user.
     * @see #getAvailableCertificateProfiles() 
     */
    public boolean isCertificateProfileListShown() throws Exception {
        return getAvailableCertificateProfiles().length != 1;
    }
	
	/** Returns the certificate profile the user is registered with
	 * 
	 * @return certificate profile name
	 * @throws Exception id an error occurs
	 */
	public String getUserCertificateProfile() throws Exception {
		return getUserCertificateProfile(defaultUsername);
	}
	
	/**
	 * Checks if the "OpenVPN installer" option should be available.
	 */
	public boolean isOpenVPNInstallerConfigured() throws Exception {
        // Check that the OpenVPN installer script exists 
        final String script = WebConfiguration.getOpenVPNCreateInstallerScript();
        boolean exists = (script != null && new File(script).exists());
        
        if (log.isDebugEnabled()) {
            log.debug("OpenVPN installer script does not exist, so the option will be hidden: " + script);
        }
        
        return exists;
	}

}
