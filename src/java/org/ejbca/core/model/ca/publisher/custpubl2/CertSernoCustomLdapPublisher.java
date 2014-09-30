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
 
package org.ejbca.core.model.ca.publisher.custpubl2;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;

/**
 * A custom LDAP publisher that publishes User Entries with Certificate Serial Number. 
 * The purpose is that you can search for certificates in the LDAP directory on certificate serial number, and each certificate is stored in one entry in the LDAP directory.
 *
 * The publisher inherits the standard LDAP publisher, but always makes sure that UID=certSerno (in decimal format) is set in the UserDN that is passed to publishing.
 * If the publisher is configured to use UID as "Use Fields in LDAP DN" this will be used in the LDAP DN of the entry created.
 * Configuration options are the same as for the standard LDAP publisher, but must be set using properties, as custom publishers are configured with a properties field.
 * 
 * To build using ejbca-custom:
 * 1. Create a directory ejbca-custom/src/java/org/ejbca/core/model/ca/publisher/custpubl2 on the same level as your ejbca directory:
 *    ejbca_6_0_0
 *    ejbca-custom
 * 2. Copy CertSernoCustomLdapPublisher.java to this directory
 * 3. Build and re-deploy EJBCA with 'ant clean; ant bootstrap'
 * 
 * To use:
 * 1. In EJBCA 6 and later, configure web.properties with web.manualclasspathsenabled=true
 * 2. Create a new Custom Publisher in EJBCA
 * 3. Specify the class path: org.ejbca.core.model.ca.publisher.custpubl2.CertSernoCustomLdapPublisher
 * 4. Set properties (use the example normal config below)
 * 5. Save and test connection
 * 
 * A normal configuration that should work in most cases (just change values to match your LDAP server) looks like:
 * 
hostname localhost
port 1389
baswdn dc=example,dc=com
logindn cn=Directory Manager
loginpassword foo123
usefieldsinldapdn 1
 * 
 * usefieldsinldapdn uses decimal values from DNFieldExtractor where the most important are: 1=UID, 2=CN, 8=OU, 9=O
 * 
 * With the configuration above certificate entries with LDAP DN "UID=123456789,dc=example,dc=com" (where 123456789 is the certificate serial number in decimal format)
 * will be added to the LDAP directory. The tree of the base DN (dc=example,dc=com) must exist already.
 * 
 * If you want to use a custom LDAP schema, such as the inetOrgPersonWithCertSerno, you can set this property, for example:
 * 
userobjectclass top;person;organizationalPerson;inetOrgPerson;inetOrgPersonWithCertSerno
 * 
 * Possible options for the properties field are (default values in parenthesis):
 * 
baswdn (misspelled, but it must be like this)
logindn
loginpassword
hostname
port (389)
connectionsecurity (STARTTLS)
timeout (5000)
readtimeout (30000)
storetimeout (60000)
createnonexisting (true)
modifyexisting (true)
addnonexistingattr (true)
modifyexistingattr (false)
userobjectclass (top;person;organizationalPerson;inetOrgPerson)
caobjectclass (top;applicationProcess;certificationAuthority-V2)
usercertattribute (userCertificate;binary)
cacertattribute (cACertificate;binary)
crlattribute (certificateRevocationList;binary)
deltacrlattribute (deltaRevocationList;binary)
arlattribute (authorityRevocationList;binary)
addmultiplecertificates (false)
removerevoked (true)
removeusersoncertrevoke (false)
createintermediatenodes (false)
setuserpasssword (false)
usefieldsinldapdn
 *
 * In most cases default values are good. 
 *
 * @version $Id$
 */
public class CertSernoCustomLdapPublisher extends LdapPublisher implements ICustomPublisher {


    private static final long serialVersionUID = -584431431033065114L;
    private static final Logger log = Logger.getLogger(CertSernoCustomLdapPublisher.class);

    @Override
    public void init(Properties properties) {
        if (log.isDebugEnabled()) {
            log.debug(">init");
        }
        // Transfer Properties into data used in LdapPublisher
        Enumeration<Object> keys = properties.keys();
        while (keys.hasMoreElements()) {
            final String key = (String)keys.nextElement();
            final String value = properties.getProperty(key);
            if (log.isDebugEnabled()) {
                log.debug("Setting property: "+key+","+value);
            }
            if (key.equals("usefieldsinldapdn")) {
                // Create use fieldsin ldapDN, it is a Collection that needs to be created
                Collection<Integer> usefieldinldapdn = new ArrayList<Integer>();
                String[] values = StringUtils.split(value, ',');
                for (int i = 0; i < values.length; i++) {
                    usefieldinldapdn.add(Integer.valueOf(values[i]));
                    setUseFieldInLdapDN(usefieldinldapdn);
                }
            } else if (key.equals("connectionsecurity")) {
                if ("PLAIN".equalsIgnoreCase(value)) {
                    setConnectionSecurity(ConnectionSecurity.PLAIN);                    
                } else if ("STARTTLS".equalsIgnoreCase(value)) {
                    setConnectionSecurity(ConnectionSecurity.STARTTLS);                    
                } else if ("SSL".equalsIgnoreCase(value)) {
                    setConnectionSecurity(ConnectionSecurity.SSL);                    
                } 
            } else {
                // Booleans should be added as Booleans, not strings
                if ("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value)) {
                    data.put(key, Boolean.valueOf(value));
                } else {
                    // Everything else added as String
                    data.put(key, value);                    
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug(">init");
        }        
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException{
        userDN = getUidCertSernoDN(incert, username, userDN);
        if (log.isDebugEnabled()) {
            log.debug("storeCertificate: "+userDN);
        }
        return super.storeCertificate(admin, incert, username, password, userDN, cafp, status, type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);
    }

    private String getUidCertSernoDN(Certificate incert, String username, String userDN) {
        // Construct the userDN with the certificate serial number as UID
        X509Certificate xcert = (X509Certificate)incert;
        String certSerNo = xcert.getSerialNumber().toString();
        String snfromuser = CertTools.getPartFromDN(userDN, "UID");
        if (StringUtils.isNotEmpty(snfromuser)) {
            log.info("User '"+username+"' aready has a UID in DN, this will be replaced by Cert Serial No: "+snfromuser);
            StringUtils.replace(userDN, snfromuser, certSerNo);
        } else {
            if (StringUtils.isEmpty(userDN)) {
                userDN = "UID="+certSerNo;
            } else {
                userDN += ",UID="+certSerNo;                
            }
        }
        return userDN;
    }

    @Override
    public void revokeCertificate(AuthenticationToken admin, Certificate cert, String username, int reason, String userDN) throws PublisherException {
        userDN = getUidCertSernoDN(cert, username, userDN);
        if (log.isDebugEnabled()) {
            log.debug("revokeCertificate: "+userDN);
        }
        super.revokeCertificate(admin, cert, username, reason, userDN);
    }

    @Override
    protected LDAPAttributeSet getAttributeSet(Certificate cert, String objectclass, String dn, String email, boolean extra, boolean person,
            String password, ExtendedInformation extendedinformation) {
        LDAPAttributeSet set = super.getAttributeSet(cert, objectclass, dn, email, extra, person, password, extendedinformation);
        // Add SerialNumber (from DN) attribute as well, it is not included by default by LDAPPublisher
        String serno = CertTools.getPartFromDN(dn, "SN");
        if (serno != null) {
            set.add(new LDAPAttribute("serialNumber", serno));
        }
        return set;
    }
}
