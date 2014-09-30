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
 
package org.ejbca.core.protocol.xkms.client;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.LocateRequestType;
import org.w3._2002._03.xkms_.LocateResultType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;





/**
 * Performes KISS calls to an web service.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class LocateCommand extends XKMSCLIBaseCommand implements IAdminCommand{

	private static Logger log = Logger.getLogger(LocateCommand.class);
			
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static final int ARG_QUERYTYPE          = 1;
	private static final int ARG_QUERYVALUE         = 2;
	private static final int ARG_KEYUSAGE           = 3;
	private static final int ARG_RESPONDWITH        = 4;
	private static final int ARG_VALIDATEFLAG       = 5;
	private static final int ARG_ENCODING           = 6;
	private static final int ARG_OUTPUTPATH         = 7;
	        
    private static final String VALIDATION_VALIDATE        = "validate";
    private static final String VALIDATION_NOVALIDATION    = "novalidation";

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
            	System.exit(-1); // NOPMD, this is not a JEE app
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
            Collection<String> respondWith = getResponseWith(args[ARG_RESPONDWITH]);
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
            
            List<? extends KeyBindingAbstractType> keyBindings = new ArrayList<KeyBindingAbstractType>();
            if(validate){
            	ValidateRequestType validationRequestType = xKMSObjectFactory.createValidateRequestType();
            	validationRequestType.setId(reqId);
                Iterator<String> iter = respondWith.iterator();
                while(iter.hasNext()){
                	validationRequestType.getRespondWith().add((String) iter.next());
                }
                validationRequestType.setQueryKeyBinding(queryKeyBindingType);
                getPrintStream().println("Sending validation request with id " + reqId + " to XKMS Service");
                if (clientCert == null) {
                    log.info("Client cert was not found and will not be used.");
                }
                ValidateResultType validateResult = getXKMSInvoker().validate(validationRequestType, clientCert, privateKey);                
                keyBindings = validateResult.getKeyBinding();                                
                
            }else{
            	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
            	locateRequestType.setId(reqId);
                Iterator<String> iter = respondWith.iterator();
                while(iter.hasNext()){
                	locateRequestType.getRespondWith().add((String) iter.next());
                }
                locateRequestType.setQueryKeyBinding(queryKeyBindingType);
                
                getPrintStream().println("Sending locate request with id " + reqId + " to XKMS Service");
                if (clientCert == null) {
                    log.info("Client cert was not found and will not be used.");
                }
                LocateResultType locateResult = getXKMSInvoker().locate(locateRequestType, clientCert, privateKey);
                keyBindings = locateResult.getUnverifiedKeyBinding();                                                
            }

            if(keyBindings.size() > 0){
            	getPrintStream().println("\n  The query matched " + keyBindings.size() + " certificates :");
                Iterator<? extends KeyBindingAbstractType> iter = keyBindings.iterator();
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

 

	private void displayAndOutputCert(UnverifiedKeyBindingType next, String outputPath, boolean pEMEncoding) throws CertificateException, CRLException, IOException {
		List<Object> keyInfos = next.getKeyInfo().getContent();

		Iterator<Object> iter = keyInfos.iterator();
		while(iter.hasNext()){
			Object obj = iter.next();
			if(obj instanceof JAXBElement){
				@SuppressWarnings("unchecked")
                JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) obj; 
				Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
				while(iter2.hasNext()){
					@SuppressWarnings("unchecked")
                    JAXBElement<byte[]> next2 = (JAXBElement<byte[]>) iter2.next();					
					String filename = "";
					if(next2.getName().getLocalPart().equals("X509Certificate")){
						byte[] encoded = (byte[]) next2.getValue();
						Certificate nextCert = CertTools.getCertfromByteArray(encoded);
						getPrintStream().println("  Found certificate with DN " + CertTools.getSubjectDN(nextCert) + " issued by " + CertTools.getIssuerDN(nextCert));

						if(pEMEncoding){
							filename = outputPath + CertTools.getPartFromDN(CertTools.getSubjectDN(nextCert), "CN") + ".pem";
							FileOutputStream fos = new FileOutputStream(filename);
							ArrayList<Certificate> certs = new ArrayList<Certificate>();
							certs.add(nextCert);
							byte[] pemData = CertTools.getPemFromCertificateChain(certs);
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
    	System.exit(-1); // NOPMD, this is not a JEE app
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
    	System.exit(-1); // NOPMD, this is not a JEE app
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
    	System.exit(-1); // NOPMD, this is not a JEE app
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
    	System.exit(-1); // NOPMD, this is not a JEE app
    	return false;
	}

	
	protected void usage() {
		getPrintStream().println("Command used to locate and optionaly validate a certificate");
		getPrintStream().println("Usage : locate <querytype> <queryvalue> <keyusage> <respondwith> <"+VALIDATION_VALIDATE+"|"+VALIDATION_NOVALIDATION+"> <der|pem> <outputpath (optional)> \n\n");
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
        getPrintStream().println("Example: locate TLSHTTP \"John Doe\" SIGNATURE X509CERT "+VALIDATION_VALIDATE+" pem");
        getPrintStream().println("Returns the signing certificate belonging to CN=John Doe and specifies if it is valid to the current directory");
        
            	        
	}


}
