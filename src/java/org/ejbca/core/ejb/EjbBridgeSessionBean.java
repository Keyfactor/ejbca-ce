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

package org.ejbca.core.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.core.ejb.authorization.AdminEntitySessionLocal;
import org.cesecore.core.ejb.authorization.AdminGroupSessionLocal;
import org.cesecore.core.ejb.ca.crl.CrlCreateSessionLocal;
import org.cesecore.core.ejb.ca.crl.CrlSessionLocal;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.cesecore.core.ejb.log.OldLogSessionLocal;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CaSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;

/**
 * Due to the lack of standardization in JEE5 there is no way to lookup local interfaces.
 * 
 * This Stateless Session Bean (SSB) act as a bridge between calling classes in the same JVM,
 * and the real ejb references.
 * 
 * This will allow us to define a single (this) local EJB in all web.xml and ejb-jar.xml files
 * and are then free to change and move around SSBs and their interfaces without XML changes.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbBridgeSessionBean implements EjbBridgeSessionLocal {

	@EJB AdminEntitySessionLocal adminEntitySession;
	@EJB AdminGroupSessionLocal adminGroupSession;
	@EJB ApprovalSessionLocal approvalSession;
	@EJB AuthorizationSessionLocal authorizationSession;
	@EJB AuthenticationSessionLocal authSession;
	@EJB CAAdminSessionLocal caAdminSession;
	@EJB CaSessionLocal caSession;
	@EJB CertificateProfileSessionLocal certificateProfileSession;
	@EJB CertificateStoreSessionLocal certificateStoreSession;
	@EJB CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
	@EJB CrlSessionLocal createCRLSession;
	@EJB CrlCreateSessionLocal crlStoreSession;
	@EJB EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB HardTokenBatchJobSessionLocal hardTokenBatchJobSession;
	@EJB HardTokenSessionLocal hardtokenSession;
	@EJB KeyRecoverySessionLocal keyRecoverySession;
	@EJB LogSessionLocal logSession;
	@EJB OldLogSessionLocal oldLogSession;
	@EJB PublisherQueueSessionLocal publisherQueueSession;
	@EJB PublisherSessionLocal publisherSession;
	@EJB RaAdminSessionLocal raSession;
	@EJB ServiceSessionLocal serviceSession;
	@EJB SignSessionLocal signSession;
	@EJB UserDataSourceSessionLocal userDataSourceSession;
	@EJB UserAdminSessionLocal userSession;

	public ApprovalSessionLocal getApprovalSession() { return approvalSession; }
	public AdminGroupSessionLocal getAdminGroupSession() { return adminGroupSession; }
	public AuthorizationSessionLocal getAuthorizationSession() { return authorizationSession; }
	public AuthenticationSessionLocal getAuthenticationSession() { return authSession; }
	public CAAdminSessionLocal getCaAdminSession() { return caAdminSession; }
	public CaSessionLocal getCaSession() { return caSession; }
	public CertificateProfileSessionLocal getCertificateProfileSession() { return certificateProfileSession; }
	public CertificateStoreSessionLocal getCertificateStoreSession() { return certificateStoreSession; }
	public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return cmpMessageDispatcherSession; }
	public CrlSessionLocal getCreateCRLSession() { return createCRLSession; }
	public CrlCreateSessionLocal getCrlStoreSession() { return crlStoreSession; }
	public EndEntityProfileSessionLocal getEndEntityProfileSession() { return endEntityProfileSession; }
	public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() { return hardTokenBatchJobSession; }
	public HardTokenSessionLocal getHardtokenSession() { return hardtokenSession; }
	public KeyRecoverySessionLocal getKeyRecoverySession() { return keyRecoverySession; }
	public LogSessionLocal getLogSession() { return logSession; }
	public OldLogSessionLocal getOldLogSession() { return oldLogSession; }
	public PublisherQueueSessionLocal getPublisherQueueSession() { return publisherQueueSession; }
	public PublisherSessionLocal getPublisherSession() { return publisherSession; }
	public RaAdminSessionLocal getRaSession() { return raSession; }
	public ServiceSessionLocal getServiceSession() { return serviceSession; }
	public SignSessionLocal getSignSession() { return signSession; }
	public UserDataSourceSessionLocal getUserDataSourceSession() { return userDataSourceSession; }
	public UserAdminSessionLocal getUserSession() { return userSession; }
	public AdminEntitySessionLocal getAdminEntitySession() { return adminEntitySession; }
}
