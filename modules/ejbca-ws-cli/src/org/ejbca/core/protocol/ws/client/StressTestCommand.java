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
package org.ejbca.core.protocol.ws.client;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.query.BasicMatch;

/**
 * @author Lars Silven, PrimeKey Solutions AB
 * @version $Id$
 */
public class StressTestCommand extends EJBCAWSRABaseCommand implements IAdminCommand {
	final static private String USER_NAME_TAG = "<userName>";
	final PerformanceTest performanceTest;
	enum TestType {
		BASIC,
		BASICSINGLETRANS,
		REVOKE,
		REVOKE_BACKDATED,
		REVOKEALOT
	}
	private class MyCommandFactory implements CommandFactory {
		final private String caName;
		final private String endEntityProfileName;
		final private String certificateProfileName;
		final private TestType testType;
		final private int maxCertificateSN;
		final private String subjectDN;
		MyCommandFactory( String _caName, String _endEntityProfileName, String _certificateProfileName,
						  TestType _testType, int _maxCertificateSN, String _subjectDN ) {
			this.testType = _testType;
			this.caName = _caName;
			this.endEntityProfileName = _endEntityProfileName;
			this.certificateProfileName = _certificateProfileName;
			this.maxCertificateSN = _maxCertificateSN;
			this.subjectDN = _subjectDN;
		}
		@Override
		public Command[] getCommands() throws Exception {
			final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			final EjbcaWS ejbcaWS = getEjbcaRAWSFNewReference();
			final JobData jobData = new JobData(this.subjectDN);
			switch (this.testType) {
			case BASIC:
				return new Command[]{
									 new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, true, this.maxCertificateSN),
									 new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData) };
			case BASICSINGLETRANS:
				return new Command[]{
									 new CertificateRequestCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, true, this.maxCertificateSN, kpg.generateKeyPair())
									};
			case REVOKE_BACKDATED:
			case REVOKE:
				return new Command[]{
									 new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, true, this.maxCertificateSN),
									 new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData),
									 new FindUserCommand(ejbcaWS, jobData),
									 new ListCertsCommand(ejbcaWS, jobData),
									 this.testType.equals(TestType.REVOKE_BACKDATED) ? new RevokeCertBackdatedCommand(ejbcaWS, jobData) : new RevokeCertCommand(ejbcaWS, jobData),
									 new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, false, -1),
									 new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData) };
			case REVOKEALOT:
				return new Command[]{
									 new MultipleCertsRequestsForAUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, kpg),
									 new FindUserCommand(ejbcaWS, jobData),
									 new ListCertsCommand(ejbcaWS, jobData),
									 new RevokeCertCommand(ejbcaWS, jobData)//,
									 };
			default:
				return null;
			}
		}
	}
	class JobData {
		String userName;
		String passWord;
		final String subjectDN;
		X509Certificate userCertsToBeRevoked[];
		public JobData(String subjectDN) {
			this.subjectDN = subjectDN;
		}
		String getDN() {
			return this.subjectDN.replace(USER_NAME_TAG, this.userName);
		}
		@Override
		public String toString() {
			return "Username '"+this.userName+"' with password '"+this.passWord+"'."; 
		}
	}
	private class BaseCommand {
		final protected JobData jobData;
		BaseCommand(JobData _jobData) {
			this.jobData = _jobData;
		}
		@Override
		public String toString() {
			return "Class \'" +this.getClass().getCanonicalName()+"' with this job data: "+ this.jobData.toString();
		}
	}
	private class Pkcs10RequestCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		final private PKCS10CertificationRequest pkcs10;
		Pkcs10RequestCommand(EjbcaWS _ejbcaWS, KeyPair keys, JobData _jobData) throws Exception {
			super(_jobData);
			this.pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"), keys.getPublic(), new DERSet(),
	                keys.getPrivate(), null);
			this.ejbcaWS = _ejbcaWS;
		}
		@Override
		public boolean doIt() throws Exception {
			final CertificateResponse certificateResponse = this.ejbcaWS.pkcs10Request(this.jobData.userName, this.jobData.passWord,
																					   new String(Base64.encode(this.pkcs10.getEncoded())),null,CertificateHelper.RESPONSETYPE_CERTIFICATE);
			return checkAndLogCertificateResponse(certificateResponse, this.jobData);
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent signing certificates";
		}
	}

	/**
	 * @param certificateResponse
	 * @throws CertificateException
	 */
	private boolean checkAndLogCertificateResponse(
			final CertificateResponse certificateResponse, final JobData jobData)
					throws CertificateException {
		X509Certificate cert = null;
		for ( final java.security.cert.Certificate tmp : CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(Base64.decode(certificateResponse.getData()))) ) {
			cert = (X509Certificate)tmp;
		}
		if ( cert==null ) {
			StressTestCommand.this.performanceTest.getLog().error("no certificate generated for user "+jobData.userName);
			return false;
		}
		final String commonName = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "CN");
		if ( !commonName.equals(jobData.userName) ) {
			StressTestCommand.this.performanceTest.getLog().error("Cert not created for right user. Username: \""+jobData.userName+"\" Subject DN: \""+cert.getSubjectDN()+"\".");
			return false;
		}
		StressTestCommand.this.performanceTest.getLog().info("Cert created. Subject DN: \""+cert.getSubjectDN()+"\".");
		StressTestCommand.this.performanceTest.getLog().result(CertTools.getSerialNumber(cert));
		return true;
	}

	private class MultipleCertsRequestsForAUserCommand extends BaseCommand implements Command {
		final EjbcaWS ejbcaWS;
		final String caName;
		final String endEntityProfileName;
		final String certificateProfileName;
		final KeyPairGenerator kpg;
		MultipleCertsRequestsForAUserCommand(EjbcaWS _ejbcaWS, String _caName, String _endEntityProfileName, String _certificateProfileName, JobData _jobData, KeyPairGenerator _kpg) throws Exception {
			super(_jobData);
			this.caName = _caName;
			this.endEntityProfileName = _endEntityProfileName;
			this.certificateProfileName = _certificateProfileName;
			this.kpg = _kpg;
			this.ejbcaWS = _ejbcaWS;
		}
		@Override
		public boolean doIt() throws Exception {
			boolean createUser = true;
			for (int i=0; i<50; i++) {
				EditUserCommand editUserCommand = new EditUserCommand(this.ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, this.jobData, createUser, -1);
				if (!editUserCommand.doIt()) {
					StressTestCommand.this.performanceTest.getLog().error("MultiplePkcs10RequestsCommand failed for "+this.jobData.userName);
					return false;
				}
				createUser = false;
				Pkcs10RequestCommand pkcs10RequestCommand = new Pkcs10RequestCommand(this.ejbcaWS, this.kpg.generateKeyPair(), this.jobData);
				if (!pkcs10RequestCommand.doIt()) {
					StressTestCommand.this.performanceTest.getLog().error("MultiplePkcs10RequestsCommand failed for "+this.jobData.userName);
					return false;
				}
			}
			return true;
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent creating a lot of certificates";
		}
	}
	private class FindUserCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		FindUserCommand(EjbcaWS _ejbcaWS, JobData _jobData) throws Exception {
			super(_jobData);
			this.ejbcaWS = _ejbcaWS;
		}
		@Override
		public boolean doIt() throws Exception {
			final org.ejbca.core.protocol.ws.client.gen.UserMatch match = new org.ejbca.core.protocol.ws.client.gen.UserMatch();
			match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
			match.setMatchvalue(this.jobData.getDN());
			match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
			final List<UserDataVOWS> result = this.ejbcaWS.findUser(match);
			if (result.size()<1) {
				StressTestCommand.this.performanceTest.getLog().error("No users found for DN \""+this.jobData.getDN()+"\"");
				return false;
			}
			final Iterator<UserDataVOWS> i = result.iterator();
			while ( i.hasNext() ) {
				final String userName = i.next().getUsername();
				if( !userName.equals(this.jobData.userName) ) {
					StressTestCommand.this.performanceTest.getLog().error("wrong user name \""+userName+"\" for certificate with DN \""+this.jobData.getDN()+"\"");
					return false;
				}
			}
			return true;
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent looking for user";
		}
	}
	private class ListCertsCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		ListCertsCommand(EjbcaWS _ejbcaWS, JobData _jobData) throws Exception {
			super(_jobData);
			this.ejbcaWS = _ejbcaWS;
		}
		@Override
		public boolean doIt() throws Exception {
			final List<Certificate> result = this.ejbcaWS.findCerts(this.jobData.userName, true);
			final Iterator<Certificate> i = result.iterator();
			this.jobData.userCertsToBeRevoked = new X509Certificate[result.size()];
			for( int j=0; i.hasNext(); j++ ) {
				this.jobData.userCertsToBeRevoked[j] = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.decode(i.next().getCertificateData())));
			}
			if ( this.jobData.userCertsToBeRevoked.length < 1 ) {
				StressTestCommand.this.performanceTest.getLog().error("no cert found for user "+this.jobData.userName);
				return false;
			}

			return true;
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent finding certs for user.";
		}
	}
	private class RevokeCertCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		RevokeCertCommand(EjbcaWS _ejbcaWS, JobData _jobData) throws Exception {
			super(_jobData);
			this.ejbcaWS = _ejbcaWS;
		}
		@Override
		public boolean doIt() throws Exception {
			for (int i=0; i<this.jobData.userCertsToBeRevoked.length; i++) {
				this.ejbcaWS.revokeCert(this.jobData.userCertsToBeRevoked[i].getIssuerDN().getName(),
										this.jobData.userCertsToBeRevoked[i].getSerialNumber().toString(16),
										REVOKATION_REASON_UNSPECIFIED);
			}
			return true;
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent revoking certificates.";
		}
	}

	private class RevokeCertBackdatedCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		final String revoceTime;
		RevokeCertBackdatedCommand(EjbcaWS _ejbcaWS, JobData _jobData) throws Exception {
			super(_jobData);
			this.ejbcaWS = _ejbcaWS;
			final Calendar c = Calendar.getInstance();
			c.setTime(new Date(new Date().getTime()-1000*60*60*24));
			this.revoceTime = DatatypeConverter.printDateTime(c);
			StressTestCommand.this.performanceTest.getLog().info("Revoke time: "+this.revoceTime);
		}
		private void revokeBackdated( int i ) throws Exception {
			this.ejbcaWS.revokeCertBackdated(
					this.jobData.userCertsToBeRevoked[i].getIssuerDN().getName(),
					this.jobData.userCertsToBeRevoked[i].getSerialNumber().toString(16),
					REVOKATION_REASON_UNSPECIFIED,
					this.revoceTime);
		}
		private void revoke( int i ) throws Exception {
			this.ejbcaWS.revokeCert(
					this.jobData.userCertsToBeRevoked[i].getIssuerDN().getName(),
					this.jobData.userCertsToBeRevoked[i].getSerialNumber().toString(16),
					REVOKATION_REASON_UNSPECIFIED);
		}
		@Override
		public boolean doIt() throws Exception {
			for (int i=0; i<this.jobData.userCertsToBeRevoked.length; i++) {
				try {
					revokeBackdated(i);
				} catch (RevokeBackDateNotAllowedForProfileException_Exception e) {
					revoke(i);
					StressTestCommand.this.performanceTest.getLog().info("No back dating since not allowed for the profile.");
					continue;
				}
			}
			return true;
		}
		@Override
		public String getJobTimeDescription() {
			return "Relative time spent revoking certificates.";
		}
	}
	private class EditUserCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		final private UserDataVOWS user;
		final private boolean doCreateNewUser;
		final private int bitsInCertificateSN;
		EditUserCommand(EjbcaWS _ejbcaWS, String caName, String endEntityProfileName, String certificateProfileName,
						JobData _jobData, boolean _doCreateNewUser, int _bitsInCertificateSN) {
			super(_jobData);
			this.doCreateNewUser = _doCreateNewUser;
			this.ejbcaWS = _ejbcaWS;
			this.user = new UserDataVOWS();
			this.user.setClearPwd(true);
			this.user.setCaName(caName);
			this.user.setEmail(null);
			this.user.setSubjectAltName(null);
			this.user.setStatus(EndEntityConstants.STATUS_NEW);
			this.user.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
			this.user.setEndEntityProfileName(endEntityProfileName);
			this.user.setCertificateProfileName(certificateProfileName);
			this.bitsInCertificateSN = _bitsInCertificateSN;
		}
		@Override
		public boolean doIt() throws Exception {
			if ( this.doCreateNewUser ) {
				this.jobData.passWord = "foo123";
				this.jobData.userName = "WSTESTUSER"+StressTestCommand.this.performanceTest.nextLong();
			}
			if ( this.bitsInCertificateSN>0 && this.doCreateNewUser ) {
				this.user.setCertificateSerialNumber(new BigInteger(this.bitsInCertificateSN, StressTestCommand.this.performanceTest.getRandom()));
			}
			this.user.setSubjectDN(this.jobData.getDN());
			this.user.setUsername(this.jobData.userName);
			this.user.setPassword(this.jobData.passWord);
			this.ejbcaWS.editUser(this.user);
			return true;
		}
		@Override
		public String getJobTimeDescription() {
			if ( this.doCreateNewUser ) {
				return "Relative time spent registering new users";
			}
			return "Relative time spent setting status of user to NEW";
		}
	} // EditUserCommand
	
	/**
	 * Command for using the "single transaction" certificateRequest method from EjbcaWS 
	 */
	private class CertificateRequestCommand extends BaseCommand implements Command {
		final private EjbcaWS ejbcaWS;
		final private UserDataVOWS user;
		final private boolean doCreateNewUser;
		final private int bitsInCertificateSN;
		private PKCS10CertificationRequest pkcs10;
		CertificateRequestCommand(EjbcaWS _ejbcaWS, String caName, String endEntityProfileName, String certificateProfileName,
						JobData _jobData, boolean _doCreateNewUser, int _bitsInCertificateSN, KeyPair keys) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
			super(_jobData);
			this.doCreateNewUser = _doCreateNewUser;
			this.ejbcaWS = _ejbcaWS;
			this.user = new UserDataVOWS();
			this.user.setClearPwd(true);
			this.user.setCaName(caName);
			this.user.setEmail(null);
			this.user.setSubjectAltName(null);
			this.user.setStatus(EndEntityConstants.STATUS_NEW);
			this.user.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
			this.user.setEndEntityProfileName(endEntityProfileName);
			this.user.setCertificateProfileName(certificateProfileName);
			this.bitsInCertificateSN = _bitsInCertificateSN;
			try {
                this.pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"), keys.getPublic(), new DERSet(), keys.getPrivate(), null);
            } catch (OperatorCreationException e) {
                getPrintStream().println(e.getLocalizedMessage());
                e.printStackTrace(getPrintStream());
            }
		}
		@Override
		public boolean doIt() throws Exception {
			if ( this.doCreateNewUser ) {
				this.jobData.passWord = "foo123";
				this.jobData.userName = "WSTESTUSER"+StressTestCommand.this.performanceTest.nextLong();
			}
			if ( this.bitsInCertificateSN>0 && this.doCreateNewUser ) {
				this.user.setCertificateSerialNumber(new BigInteger(this.bitsInCertificateSN, StressTestCommand.this.performanceTest.getRandom()));
			}
			this.user.setSubjectDN(this.jobData.getDN());
			this.user.setUsername(this.jobData.userName);
			this.user.setPassword(this.jobData.passWord);
			int requestType = CertificateHelper.CERT_REQ_TYPE_PKCS10;
			String responseType = CertificateHelper.RESPONSETYPE_CERTIFICATE;
			String hardTokenSN = null; // not used
			String requestData = new String(Base64.encode(this.pkcs10.getEncoded()));
			final CertificateResponse certificateResponse = this.ejbcaWS.certificateRequest(this.user, requestData, requestType, hardTokenSN, responseType);
			return checkAndLogCertificateResponse(certificateResponse, this.jobData);
		}
		@Override
		public String getJobTimeDescription() {
			if ( this.doCreateNewUser ) {
				return "Relative time spent registering new users";
			}
			return "Relative time spent setting status of user to NEW";
		}
	} // CertificateRequestCommand
	
	/**
	 * @param args
	 */
	public StressTestCommand(String[] _args) {
		super(_args);
		this.performanceTest = new PerformanceTest();
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ws.client.EJBCAWSRABaseCommand#usage()
	 */
	@Override
	protected void usage() {
		getPrintStream().println("Command used to perform a \"stress\" test of EJBCA.");
		getPrintStream().println("The command will start up a number of threads.");
		getPrintStream().println("Each thread will continuously add new users to EJBCA. After adding a new user the thread will fetch a certificate for it.");
		getPrintStream().println();
		getPrintStream().println("Usage : stress <caname> <nr of threads> <max wait time in ms to fetch cert after adding user> [<end entity profile name>] [<certificate profile name>] [<type of test>]");
		getPrintStream().println();
		getPrintStream().println("Here is an example of how the test could be started:");
		getPrintStream().println("./ejbcawsracli.sh stress ManagementCA 20 5000");
		getPrintStream().println("20 threads is started. After adding a user the thread waits between 0-500 ms before requesting a certificate for it. The certificates will all be signed by the CA ManagementCA.");
		getPrintStream().println();
		getPrintStream().println("To define a template for the subject DN of each new user use the java system property 'subjectDN'.");
		getPrintStream().println("If the property value contains one or several '<userName>' string these strings will be substituted with the user name.");
		getPrintStream().println("Example: JAVA_OPT=\"-DsubjectDN=CN=<userName>,O=Acme,UID=hej<userName>,OU=,OU=First Fixed,OU=sfsdf,OU=Middle Fixed,OU=fsfsd,OU=Last Fixed\" ../../PWE/ejbca_3_11/dist/clientToolBox/ejbcaClientToolBox.sh EjbcaWsRaCli stress ldapDirect 1 1000 ldapClientOUTest ldapClientDirect");
		getPrintStream().print("Types of stress tests:");
		TestType testTypes[] = TestType.values();
		for ( TestType testType : testTypes ) {
			getPrintStream().print(" " + testType);
		}
		getPrintStream().println();
	}

	@Override
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

		try {
			if(this.args.length <  2){
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}
			final int numberOfThreads = this.args.length>2 ? Integer.parseInt(this.args[2]) : 1;
			final int waitTime = this.args.length>3 ? Integer.parseInt(this.args[3]) : -1;
			final String caName = this.args[1];
			final String endEntityProfileName = this.args.length>4 ? this.args[4] : "EMPTY";
			final String certificateProfileName = this.args.length>5 ? this.args[5] : "ENDUSER";
			final TestType testType = this.args.length>6 ? TestType.valueOf(this.args[6]) : TestType.BASIC;
			final int maxCertificateSN;
			final String subjectDN = System.getProperty("subjectDN", "CN="+USER_NAME_TAG);
			{
				final String sTmp = System.getProperty("maxCertSN");
				int iTmp;
				try {
					iTmp = sTmp!=null && sTmp.length()>0 ? Integer.parseInt(sTmp) : -1;
				} catch ( NumberFormatException e ) {
					iTmp = -1;
				}
				maxCertificateSN = iTmp;
			}
			this.performanceTest.execute(new MyCommandFactory(caName, endEntityProfileName, certificateProfileName, testType, maxCertificateSN, subjectDN),
										 numberOfThreads, waitTime, getPrintStream());
			getPrintStream().println("A test key for each thread is generated. This could take some time if you have specified many threads and long keys.");
			synchronized(this) {
				wait();
			}
		} catch( InterruptedException e) {
			// do nothing since user wants to exit.
		} catch( Exception e) {
			throw new ErrorAdminCommandException(e);
		}finally{
			this.performanceTest.getLog().close();
		}
	}
}
