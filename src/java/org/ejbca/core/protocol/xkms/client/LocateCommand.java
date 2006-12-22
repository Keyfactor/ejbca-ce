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
 
package org.ejbca.core.protocol.xkms.client;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.xml.bind.JAXBElement;

import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.LocateRequestType;
import org.w3._2002._03.xkms_.LocateResultType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.StatusType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;





/**
 * Performes KISS calls to an web service.
 *
 * @version $Id: LocateCommand.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 * @author Philip Vendil
 */
public class LocateCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_QUERYTYPE          = 1;
	private static final int ARG_QUERYVALUE         = 2;
	private static final int ARG_KEYUSAGE           = 3;
	private static final int ARG_RESPONDWITH        = 4;
	private static final int ARG_VALIDATEFLAG       = 5;
	private static final int ARG_ENCODING           = 6;
	private static final int ARG_OUTPUTPATH         = 7;
	
	private static final String QUERYTYPE_CERT               = "CERT";			
	private static final String QUERYTYPE_SMIME              = "SMIME";	
	private static final String QUERYTYPE_TLS                = "TLS";
	private static final String QUERYTYPE_TLSHTTP            = "TLSHTTP";
	private static final String QUERYTYPE_TLSSMTP            = "TLSSMTP";
	private static final String QUERYTYPE_IPSEC              = "IPSEC";
	private static final String QUERYTYPE_PKIX               = "PKIX";
	
	private static final String KEYUSAGE_ALL                  = "ALL";
	private static final String KEYUSAGE_SIGNATURE            = "SIGNATURE";
    private static final String KEYUSAGE_ENCRYPTION           = "ENCRYPTION";
    private static final String KEYUSAGE_EXCHANGE             = "EXCHANGE";
    
    private static final String RESPONDWITH_X509CERT           = "X509CERT";
    private static final String RESPONDWITH_X509CHAIN          = "X509CHAIN";
    private static final String RESPONDWITH_X509CHAINANDCRL    = "X509CHAINANDCRL";
    
    private static final String VALIDATION_VALIDATE        = "validate";
    private static final String VALIDATION_NOVALIDATION    = "novalidation";

    private static final String ENCODING_PEM        = "pem";
    private static final String ENCODING_DER        = "der";
	
    /**
     * Creates a new instance of RaAddUserCommand
     *
     * @param args command line arguments
     */
    public LocateCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
    	
        try {   
           
            if(args.length < 7 || args.length > 8){
            	usage();
            	System.exit(-1);
            }
            
            boolean isCertQuery = args[ARG_QUERYTYPE].equalsIgnoreCase(QUERYTYPE_CERT);
            
            String queryType = getQueryType(args[ARG_QUERYTYPE]);
            
            byte[] queryCert = null;
            String queryVal = null;
            if(isCertQuery){
            	queryCert = loadCert(args[ARG_QUERYVALUE]);
            }else{
            	queryVal = args[ARG_QUERYVALUE];
            }
            
            boolean validate = getValidate(args[ARG_VALIDATEFLAG]);
            boolean pEMEncoding = usePEMEncoding(args[ARG_ENCODING]);
            String keyUsage = getKeyUsage(args[ARG_KEYUSAGE]);
            Collection respondWith = getResponseWith(args[ARG_RESPONDWITH]);
            String outputPath = "";
            if(args.length >= ARG_OUTPUTPATH +1){
            	if(args[ARG_OUTPUTPATH] != null){
            	  outputPath = args[ARG_OUTPUTPATH] + "/";            	            	
            	}
            }

            
            QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
            if(isCertQuery){
            	X509DataType x509DataType = sigFactory.createX509DataType();
                x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(queryCert));
                KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
                keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
                queryKeyBindingType.setKeyInfo(keyInfoType);
            }else{
            	UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
            	useKeyWithType.setApplication(queryType);
            	useKeyWithType.setIdentifier(queryVal);
            	queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
            }
            if(keyUsage != null){
              queryKeyBindingType.getKeyUsage().add(keyUsage);
            }
            
            String reqId = genId();
            
            List keyBindings = new ArrayList();
            if(validate){
            	ValidateRequestType validationRequestType = xKMSObjectFactory.createValidateRequestType();
            	validationRequestType.setId(reqId);
                Iterator iter = respondWith.iterator();
                while(iter.hasNext()){
                	validationRequestType.getRespondWith().add((String) iter.next());
                }
                validationRequestType.setQueryKeyBinding(queryKeyBindingType);
                getPrintStream().println("Sending validation request with id " + reqId + " to XKMS Service");
                
                ValidateResultType validateResult = getXKMSInvoker().validate(validationRequestType, clientCert, privateKey);                
                keyBindings = validateResult.getKeyBinding();                                
                
            }else{
            	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
            	locateRequestType.setId(reqId);
                Iterator iter = respondWith.iterator();
                while(iter.hasNext()){
                	locateRequestType.getRespondWith().add((String) iter.next());
                }
                locateRequestType.setQueryKeyBinding(queryKeyBindingType);
                
                getPrintStream().println("Sending locate request with id " + reqId + " to XKMS Service");
                LocateResultType locateResult = getXKMSInvoker().locate(locateRequestType, clientCert, privateKey);
                keyBindings = locateResult.getUnverifiedKeyBinding();                                                
            }

            if(keyBindings.size() > 0){
            	getPrintStream().println("\n  The query matched " + keyBindings.size() + " certificates :");
            	Iterator iter = keyBindings.iterator();
            	while(iter.hasNext()){
            		UnverifiedKeyBindingType next = (UnverifiedKeyBindingType) iter.next();
            		displayAndOutputCert(next, outputPath, pEMEncoding);            		
            		if(next instanceof KeyBindingType){
            			displayStatus((KeyBindingType) next);
            		}            		            		
            		getPrintStream().println("\n\n\n");
            	}
            }else{
            	getPrintStream().println("\n  The query didn't match any certificates");
            }
        
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private void displayStatus(KeyBindingType type) {
		StatusType status = type.getStatus();
		getPrintStream().println("  The certificate had the following status");
		getPrintStream().println("  Valid:");
		displayStatusReasons(status.getValidReason());
		getPrintStream().println("  Indeterminable:");
		displayStatusReasons(status.getIndeterminateReason());
		getPrintStream().println("  Invalid:");
		displayStatusReasons(status.getInvalidReason());
		
	}

	private void displayStatusReasons(List<String> reasons) {
		if(reasons.size() == 0){
			getPrintStream().println("      NONE");
		}else{
			Iterator<String> iter = reasons.iterator();
			while(iter.hasNext()){
				String next = iter.next();
				if(next.equals(XKMSConstants.STATUSREASON_ISSUERTRUST)){
					getPrintStream().println("      ISSUERTRUST");
				}
				if(next.equals(XKMSConstants.STATUSREASON_REVOCATIONSTATUS)){
					getPrintStream().println("      REVOCATIONSTATUS");
				}
				if(next.equals(XKMSConstants.STATUSREASON_SIGNATURE)){
					getPrintStream().println("      SIGNATURE");
				}
				if(next.equals(XKMSConstants.STATUSREASON_VALIDITYINTERVAL)){
					getPrintStream().println("      VALIDITYINTERVAL");
				}
			}
		}
	}

	private void displayAndOutputCert(UnverifiedKeyBindingType next, String outputPath, boolean pEMEncoding) throws CertificateException, CRLException, IOException {
		List keyInfos = next.getKeyInfo().getContent();

		Iterator iter = keyInfos.iterator();
		while(iter.hasNext()){
			Object obj = iter.next();
			if(obj instanceof JAXBElement){
				JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) obj; 
				Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
				while(iter2.hasNext()){
					JAXBElement next2 = (JAXBElement) iter2.next();					
					String filename = "";
					if(next2.getName().getLocalPart().equals("X509Certificate")){
						byte[] encoded = (byte[]) next2.getValue();
						X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
						getPrintStream().println("  Found certificate with DN " + CertTools.getSubjectDN(nextCert) + " issued by " + CertTools.getIssuerDN(nextCert));

						if(pEMEncoding){
							filename = outputPath + CertTools.getPartFromDN(CertTools.getSubjectDN(nextCert), "CN") + ".pem";
							FileOutputStream fos = new FileOutputStream(filename);
							ArrayList certs = new ArrayList();
							certs.add(nextCert);
							byte[] pemData = CertTools.getPEMFromCerts(certs);
							fos.write(pemData);
							fos.close();					  
						}else{
							filename = outputPath + CertTools.getPartFromDN(CertTools.getSubjectDN(nextCert), "CN") + ".cer";
							FileOutputStream fos = new FileOutputStream(filename);
							fos.write(nextCert.getEncoded());
							fos.close();
						}  				  
					}
					if(next2.getName().getLocalPart().equals("X509CRL")){					
						byte[] encoded = (byte[]) next2.getValue();
						X509CRL nextCRL = CertTools.getCRLfromByteArray(encoded);

						getPrintStream().println("  Found CRLissued by " + CertTools.getIssuerDN(nextCRL));
						if(pEMEncoding){
							filename = outputPath  + CertTools.getPartFromDN(CertTools.getIssuerDN(nextCRL), "CN") + "-crl.pem";
							FileOutputStream fos = new FileOutputStream(filename);
							fos.write("-----BEGIN X509 CRL-----\n".getBytes());
							fos.write(Base64.encode(nextCRL.getEncoded(), true));
							fos.write("\n-----END X509 CRL-----\n".getBytes());						
							fos.close();					  
						}else{
							filename = outputPath  + CertTools.getPartFromDN(CertTools.getIssuerDN(nextCRL), "CN") + ".crl";
							FileOutputStream fos = new FileOutputStream(filename);
							fos.write(nextCRL.getEncoded());
							fos.close();
						}
					}
					getPrintStream().println("  Written to : " + filename + "\n");
				}

				// Display use key with
				displayUseKeyWith(next);

				// Display key usage
				displayKeyUsage(next);
			}
		}		
	}

	private void displayKeyUsage(UnverifiedKeyBindingType next) {
		Iterator<String> iter = next.getKeyUsage().iterator();
		getPrintStream().println("  Certificate have the following key usage:");
		if(next.getKeyUsage().size() == 0){
			getPrintStream().println("    " + KEYUSAGE_ALL );
		}
		while(iter.hasNext()){
			String keyUsage = iter.next();
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_SIGNATURE)){
				getPrintStream().println("    " + KEYUSAGE_SIGNATURE );				
			}
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_ENCRYPTION)){
				getPrintStream().println("    " + KEYUSAGE_ENCRYPTION);				
			}
			if(keyUsage.equals(XKMSConstants.KEYUSAGE_EXCHANGE)){
				getPrintStream().println("    " + KEYUSAGE_EXCHANGE);				
			}
		}				
		
	}

	private void displayUseKeyWith(UnverifiedKeyBindingType next) {
		Iterator<UseKeyWithType> iter = next.getUseKeyWith().iterator();
		if(next.getKeyUsage().size() != 0){
			getPrintStream().println("  Certificate can be used with applications:");
			while(iter.hasNext()){
				UseKeyWithType useKeyWith = iter.next();
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_IPSEC)){
					getPrintStream().println("    " + QUERYTYPE_IPSEC + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
					getPrintStream().println("    " + QUERYTYPE_PKIX + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_SMIME)){
					getPrintStream().println("    " + QUERYTYPE_SMIME + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLS)){
					getPrintStream().println("    " + QUERYTYPE_TLS + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLSHTTP)){
					getPrintStream().println("    " + QUERYTYPE_TLSHTTP + " = " + useKeyWith.getIdentifier());				
				}
				if(useKeyWith.getApplication().equals(XKMSConstants.USEKEYWITH_TLSSMTP)){
					getPrintStream().println("    " + QUERYTYPE_TLSSMTP + " = " + useKeyWith.getIdentifier());				
				}
			}
		}
	}

	/**
     * Returns tru if 'validation' is set
     * @param arg
     */
    private boolean getValidate(String arg) {
		if(arg.equalsIgnoreCase(VALIDATION_VALIDATE)){
			return true;
		}
		
		if(arg.equalsIgnoreCase(VALIDATION_NOVALIDATION)){
			return false;
		}
		
		getPrintStream().println("Illegal validation flag " + arg);
        usage();
    	System.exit(-1);
		return false;
	}

	/**
     * Returns the query usekeywith type or null
     * if it is a certificate query
     * @param arg
     */
    private String getQueryType(String arg) {
        if(arg.equalsIgnoreCase(QUERYTYPE_CERT)){
        	return null;
        }
        
        if(arg.equalsIgnoreCase(QUERYTYPE_IPSEC)){
        	return XKMSConstants.USEKEYWITH_IPSEC;
        }
        
        if(arg.equalsIgnoreCase(QUERYTYPE_PKIX)){
        	return XKMSConstants.USEKEYWITH_PKIX;
        }
        
        if(arg.equalsIgnoreCase(QUERYTYPE_SMIME)){
        	return XKMSConstants.USEKEYWITH_SMIME;
        }
        
        if(arg.equalsIgnoreCase(QUERYTYPE_TLS)){
        	return XKMSConstants.USEKEYWITH_TLS;
        }
        
        if(arg.equalsIgnoreCase(QUERYTYPE_TLSHTTP)){
        	return XKMSConstants.USEKEYWITH_TLSHTTP;
        }

        if(arg.equalsIgnoreCase(QUERYTYPE_TLSSMTP)){
        	return XKMSConstants.USEKEYWITH_TLSSMTP;
        }
        
		getPrintStream().println("Illegal query type " + arg);
        usage();
    	System.exit(-1);
		return null;
	}

	/**
     * Method that loads a certificate from file 
     * @param filename
     * @return
     */
    private byte[] loadCert(String arg) {
		try {
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(arg));
			byte[] retval = new byte[bis.available()];
			bis.read(retval);
			return retval;
			
		} catch (FileNotFoundException e) {
			getPrintStream().println("Couldn't find file with name " + arg);
	        usage();
	    	System.exit(-1);
		} catch (IOException e) {
			getPrintStream().println("Couldn't read file with name " + arg);
	        usage();
	    	System.exit(-1);
		}
		return null;
	}

	/**
     * Returns a collection of resonswith tags.
     * 
     * @param arg
     * @return a collection of Strings containging respond with constatns
     */
    private Collection getResponseWith(String arg) {
    	ArrayList retval = new ArrayList();
		
    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CERT)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CERT);
    		return retval;
    	}

    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CHAIN)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CHAIN);
    		return retval;
    	}
    	
    	if(arg.equalsIgnoreCase(RESPONDWITH_X509CHAINANDCRL)){
    		retval.add(XKMSConstants.RESPONDWITH_X509CHAIN);
    		retval.add(XKMSConstants.RESPONDWITH_X509CRL);
    		return retval;
    	}
    	
		getPrintStream().println("Illegal response with " + arg);
        usage();
    	System.exit(-1);
		return null;
	}



	/**
     * Mthod returning the keyUsage tag or null if all i acceptable
     * @param keyusage from args
     * @return
     */
	private String getKeyUsage(String arg) {
		if(arg.equalsIgnoreCase(KEYUSAGE_ALL)){
			return null;
		}
		if(arg.equalsIgnoreCase(KEYUSAGE_SIGNATURE)){
			return XKMSConstants.KEYUSAGE_SIGNATURE;
		}
		if(arg.equalsIgnoreCase(KEYUSAGE_ENCRYPTION)){
			return XKMSConstants.KEYUSAGE_ENCRYPTION;
		}
		if(arg.equalsIgnoreCase(KEYUSAGE_EXCHANGE)){
			return XKMSConstants.KEYUSAGE_EXCHANGE;
		}		
			
		getPrintStream().println("Illegal key usage " + arg);
        usage();
    	System.exit(-1);
		return null;
	}
	
	
	/**
	 * Returns true if encoding is PEM othervise DER
	 * @return
	 */
	private boolean usePEMEncoding(String arg){
		if(arg.equalsIgnoreCase(ENCODING_PEM)){
			return true;
		}

		if(arg.equalsIgnoreCase(ENCODING_DER)){
			return false;
		}
		
		getPrintStream().println("Illegal encoding (should be pem or der) : " + arg);
        usage();
    	System.exit(-1);
    	return false;
	}

	private String genId() throws NoSuchAlgorithmException {
        BigInteger serno = null;		
        Random random = SecureRandom.getInstance("SHA1PRNG");

        long seed = Math.abs((new Date().getTime()) + this.hashCode());
        random.setSeed(seed);
		try {
	        byte[] sernobytes = new byte[8];

	        random.nextBytes(sernobytes);
	        serno = (new java.math.BigInteger(sernobytes)).abs();
	       
		} catch (Exception e) {
			getPrintStream().println("Error generating response ID " );
		}
		return serno.toString();
	}
	
	protected void usage() {
		getPrintStream().println("Command used to locate and optionaly validate a certificate");
		getPrintStream().println("Usage : locate <querytype> <queryvalue> <keyusage> <respondwith> <validate|novalidation> <der|pem> <outputpath (optional)> \n\n");
        getPrintStream().println("Querytypes are:");
        getPrintStream().println(" CERT     : Use a existing certificate from file, queryvalue should be path to certificate.\n"
        		                +" SMIME    : Lookup by the RFC882 Name of certificate\n"
        		                +" TLS      : Lookup by the URI in the certificate\n"
        		                +" TLSHTTP  : Lookup by the CN in the certificate\n"
        		                +" TSLSMTP  : Lookup by the DNS Name of the certificate\n"
        		                +" IPSEC    : Lookup by the IP address of the certificate\n"
        		                +" PKIX     : Lookup by the SubjectDN of the certificate\n");
        getPrintStream().println("Available Keyusages are:");
        getPrintStream().println(" ALL        : Any key usage will do\n"
                                +" SIGNATURE  : Return certificate that can be used for signing\n"
                                +" ENCRYPTION : Return certificate that can be used for encryption\n"
                                +" EXCHANGE   : Return certificate that can be used for exchange\n");
        getPrintStream().println("Available Respond With values are:");                
        getPrintStream().println(" X509CERT        : Respond with the certificate.\n"
                                +" X509CHAIN       : Respond with the entire certificate chain\n"
                                +" X509CHAINANDCRL : Respond with the chain and CRL\n");
        getPrintStream().println("Use 'validate' if you want the status of the certificate, othervise use 'novalidation'.\n");
        getPrintStream().println("Use 'pem' or 'der' depending on prefered encoding.\n");
        getPrintStream().println("Outputpath specifies to which directory to write certificate and CRLs, current directory is used if omitted\n\n");
        getPrintStream().println("Example: locate TLSHTTP \"John Doe\" SIGNATURE X509CERT validation pem");
        getPrintStream().println("Returns the signing certificate belonging to CN=John Doe and specifies if it is valid to the current directory");
        
            	        
	}


}
