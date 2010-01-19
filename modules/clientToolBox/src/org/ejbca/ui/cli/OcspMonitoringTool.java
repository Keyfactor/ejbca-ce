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
 
package org.ejbca.ui.cli;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateData;
import org.ejbca.util.CliTools;

/**
 * Used to synchronize OCSP databases from the CA database. 
 *
 * @version $Id$
 */
public class OcspMonitoringTool extends ClientToolBox {
	
	private static final Logger log = Logger.getLogger(OcspMonitoringTool.class);
	
	private final String ERROR_NOTEXISTINGOCSP = "Row does not exist in OCSP database.";
	private final String ERROR_NOTEXISTINGCA = "Row exists in OCSP, but not in CA database.";
	private final String ERROR_NOTEXISTINGCALIMIT = "Row exists in OCSP, but not in CA database and is too far off in the future.";
	private final String ERROR_NOTUPDATED = "Row is not updated in OCSP database.";
	private final String ERROR_UPDATEDOCSP = "OCSP database has a newer entry than CA database.";
	private final String ERROR_TAMPERED = "Row was tampered with in OCSP database.";
	private final int ERRORREPORT_SIZELIMIT = 64*1024; 
	private final int ERRORREPORT_LISTLIMIT = 32;

	final String usage = "\n"
		+ getName() + " [-ns] <inclusion-mode> <batchSize> <timeToConfirmError> <certificateProfileId1> [<certificateProfileId2>] ... - <CA db name> <OCSP1 db name> [<OCSP2 db name>] ...\n"
		+ " Compares different OCSP databases with the CA's database and reports discrepancies.\n"
		+ " This commands relies on a JPA properties/META-INF/persistence.xml being present and configured for your environment and that the systems time is correct.\n"
		+ " JDBC drivers used in persistence.xml also has to present in lib/.\n\n"
		+ " -ns                    Non-strict status comparision: Active == Notified and Revoked == Archived.\n"
		+ " inclusion-mode:        all=include actual certificate, nocert=dont include certificate in comparisons\n"
		+ " batchSize              Number of certificates to read at the time. Larger batch means faster runs, but uses up more memory.\n"
		+ " timeToConfirmError:    The number of seconds to wait before we concider a discrepancy in the OCSP as an error.\n"
		+ " certificateProfileId1: the certificateProfileId to use for monitoring\n"
		+ " -                      required separator\n"
		+ " CA db name:            persistence-unit name of CA database in the persistence.xml file\n"
		+ " OCSP1 db name:         persistence-unit name of the first OCSP database in the persistence.xml file\n"
	    + "\nCheck ctb.log for messages.";

    /**
     * @param args command line arguments
     */
    public static void main(String[] args) {
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add("dummy");
        for ( int i=0; i<args.length; i++) { // remove first argument
            lArgs.add(args[i]);
        }
        new OcspMonitoringTool().execute(lArgs.toArray(new String[]{}));
    }
    
    /*
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    String getName() {
        return "OCSPMon";
    }

	/*
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    void execute(String[] args) {
        try {
        	System.exit(executeInternal(args));
        } catch (Exception e) {
        	log.error("Error: ", e);
            System.exit(-1);
        }
    }

    /**
     * This can also be called from JUnit tests.
     */
    public int executeInternal(String[] args) throws Exception {
    	log.info("Monitoring tool started.");
    	long startTime = new Date().getTime();
    	// Parse arguments and setup entityManagers
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean strictStatus = !argsList.remove("-ns");
		args = argsList.toArray(new String[0]);
    	if (args.length<7) {
    		log.info(usage);
    		return -1;
    	}
    	boolean inclusionMode = "nocert".equalsIgnoreCase(args[1]);
    	log.info("Including all fields" + (inclusionMode ? ", except the certificate" : "") + " in comparision.");
    	int currentArg = 2;
    	int batchSize = Integer.parseInt(args[currentArg]);
    	currentArg++;
    	long timeToConfirmError = Integer.parseInt(args[currentArg]) * 1000;
    	currentArg++;
    	List<Integer> certificateProfileIds = new ArrayList<Integer>();
    	while (currentArg < args.length && !args[currentArg].equals("-")) {
    		try {
    			certificateProfileIds.add(Integer.parseInt(args[currentArg]));
    		} catch (NumberFormatException e) {
    			log.info("Certificate profile id is not a number: "+e.getLocalizedMessage());
        		log.info(usage);
        		return -1;
    		}
    		currentArg++;
    	}
		currentArg++;
    	log.info("Looking for certificates with certificateProifileIds " + certificateProfileIds + "");
    	EntityManager caEntityManager = Persistence.createEntityManagerFactory(args[currentArg]).createEntityManager();
    	final String caEntityManagerName = args[currentArg];
    	log.info("Using " + caEntityManagerName + " as reference to the CA database.");
    	currentArg++;
    	List<EntityManager> ocspEntityManagers = new ArrayList<EntityManager>();
    	List<String> ocspEntityManagerNames = new ArrayList<String>();
    	for (int i=currentArg; i<args.length; i++) {
    		ocspEntityManagerNames.add(args[i]);
    		ocspEntityManagers.add(Persistence.createEntityManagerFactory(args[i]).createEntityManager());
    	}
    	log.info("Added " + ocspEntityManagers.size() + " ocsp EntityManagers");
    	// Find out how many certificateProfileIds that are present in the different OCSPs
		for (int i=0; i<ocspEntityManagers.size(); i++) {
			EntityManager ocspEntityManager = ocspEntityManagers.get(i);
		    List<Integer> ocspCertificateProfileIds = CertificateData.getUsedCertificateProfileIds(ocspEntityManager);
		    for (Integer currentProfileId : certificateProfileIds) {
		    	if (!ocspCertificateProfileIds.remove(currentProfileId)) {
		    		log.warn("OCSP "+ ocspEntityManagerNames.get(i) + " is missing certificateProfileId " + currentProfileId + ".");
		    	}
		    }
		    if (!ocspCertificateProfileIds.isEmpty()) {
		    	log.warn("OCSP "+ ocspEntityManagerNames.get(i) + " has additional certificateProfileIds " + ocspCertificateProfileIds + ".");
		    }
		}
		// Go through all the certificateData rows and for each certificateProfileId
    	List<String> errorList = new ArrayList<String>();
	    for (Integer certificateProfileId : certificateProfileIds) {
	    	if (log.isDebugEnabled()) {
	    		log.debug("Started working on next certificateProlfileId " + certificateProfileId + ".");
	    	}
			final long initialEntries = CertificateData.getCount(caEntityManager, certificateProfileId);
			// Display some nice info about the approximate number of certificates in the different databases
			log.info("CA " + caEntityManagerName + " currently has " + initialEntries + " rows for id " + certificateProfileId);
			for (int i=0; i<ocspEntityManagers.size(); i++) {
				final long initialOcspEntries = CertificateData.getCount(ocspEntityManagers.get(i), certificateProfileId);
				log.info("OCSP " + ocspEntityManagerNames.get(i) + " currently has " + initialOcspEntries + " rows for id " + certificateProfileId);
			}
			long count = 0;
	    	String currentFingerprint = "0";	// '0' < '0000000000000000000000000000000000000000' so start with this
	    	List<CertificateData> certificateDataList;
	    	List<RecheckEntry> recheckList = new ArrayList<RecheckEntry>();
	    	// Fetch batch after batch of CertificateData from CA database until there is no more
	    	while ( (certificateDataList = CertificateData.getNextBatch(caEntityManager, certificateProfileId,  currentFingerprint, batchSize)) != null
	    			&& certificateDataList.size()>0) {
				caEntityManager.clear();	// Detach all the fetched rows
		    	if (log.isDebugEnabled()) {
		    		log.debug("Got another batch of " + certificateDataList.size() + " certificates for " + certificateProfileId + ". about "
		    				+ (initialEntries - count) + " rows left. Current memory usage is " + getUsedMemory()/1000000L + " MB.");
		    	}
	    		count += certificateDataList.size();
		    	// Compare the batch from the CA with a batch from each OCSP database
				for (int i=0; i<ocspEntityManagers.size(); i++) {
					EntityManager ocspEntityManager = ocspEntityManagers.get(i);
					String ocspEntityManagerName = ocspEntityManagerNames.get(i);
			    	if (log.isDebugEnabled()) {
			    		log.debug(" Getting batch for " + ocspEntityManagerName);
			    	}
					List<CertificateData> ocspCertificateDataList = CertificateData.getNextBatch(ocspEntityManager, certificateProfileId,  currentFingerprint, batchSize);
					ocspEntityManager.clear();	// Detach all the fetched rows
					int caRowIndex = 0;
					int ocspRowIndex = 0;
					while (caRowIndex<certificateDataList.size()) {
						if (ocspRowIndex>=ocspCertificateDataList.size()) {
					    	if (log.isDebugEnabled()) {
								log.debug("ocspRowIndex("+ocspRowIndex+")>=ocspCertificateDataList.size()("+ocspCertificateDataList.size()+") caRowIndex("+caRowIndex+")");
					    	}
							// Add the rest of CA CertificateData rows to re-check list
							for (;caRowIndex<certificateDataList.size();caRowIndex++) {
				    			recheckList.add(new RecheckEntry(certificateDataList.get(caRowIndex).getFingerprint(), certificateDataList.get(caRowIndex).getUpdateTime(), i));
							}
							continue;
						}
						// Compare one row from CA database with one row from the current OCSP responder
						CertificateData certificateData = certificateDataList.get(caRowIndex);
						CertificateData ocspCertificateData = ocspCertificateDataList.get(ocspRowIndex);
						if (!certificateData.equals(ocspCertificateData, inclusionMode, strictStatus)) {
							int test = certificateData.getFingerprint().compareTo(ocspCertificateData.getFingerprint());
					    	if (log.isDebugEnabled()) {
								log.debug("cd.fp=" + certificateData.getFingerprint() +" ocd.fp=" + ocspCertificateData.getFingerprint());
					    	}
							if (test > 0) {
								// Extra row in OCSP database
						    	if (log.isDebugEnabled()) {
									log.debug("An extra cert with fingerprint "+ocspCertificateData.getFingerprint()+" might exist in the OCSP database " + ocspEntityManagerName);
						    	}
				    			if (ocspCertificateData.getUpdateTime() > new Date().getTime()+timeToConfirmError) {
									handleError(errorList, ocspEntityManagerNames.get(i), ocspCertificateData.getFingerprint(), ocspCertificateData.getIssuerDN(), ocspCertificateData.getSerialNumber()
											,ERROR_NOTEXISTINGCALIMIT);
				    			} else {
									recheckList.add(new RecheckEntry(ocspCertificateData.getFingerprint(), ocspCertificateData.getUpdateTime(), i));
				    			}
								ocspRowIndex++;
								continue;
							} else if (test < 0) {
								// Missing row in OCSP database
						    	if (log.isDebugEnabled()) {
									log.debug("A cert with fingerprint "+certificateData.getFingerprint()+" might be missing in the OCSP database " + ocspEntityManagerName);
						    	}
								recheckList.add(new RecheckEntry(certificateData.getFingerprint(), certificateData.getUpdateTime(), i));
								caRowIndex++;
								continue;
							} else {
								// Row exists but is not equal
						    	if (log.isDebugEnabled()) {
									log.debug("A cert with fingerprint "+ocspCertificateData.getFingerprint()+" might not be in sync in the OCSP database " + ocspEntityManagerName);
						    	}
								if (certificateData.getUpdateTime() == ocspCertificateData.getUpdateTime()) {
									// Since the time is the same, someone has tampered with the rest of the data
									handleError(errorList, ocspEntityManagerName, certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
											,ERROR_TAMPERED);
								} else if (certificateData.getUpdateTime() > ocspCertificateData.getUpdateTime()) {
									// Might have a pending update for this OCSP, re-check later
							    	if (log.isDebugEnabled()) {
										log.debug("A cert with fingerprint "+ocspCertificateData.getFingerprint()+" might not have been updated in the OCSP database " + ocspEntityManagerName);
							    	}
									recheckList.add(new RecheckEntry(certificateData.getFingerprint(), certificateData.getUpdateTime(), i));
								} else {
									// An update for this OCSP might have gone through since we read the CA database, re-check later
							    	if (log.isDebugEnabled()) {
										log.debug("A cert with fingerprint "+ocspCertificateData.getFingerprint()+" in the OCSP database " + ocspEntityManagerName + " might not have been updated in the CA database.");
							    	}
					    			if (ocspCertificateData.getUpdateTime() > new Date().getTime()+timeToConfirmError) {
										handleError(errorList, ocspEntityManagerNames.get(i), ocspCertificateData.getFingerprint(), ocspCertificateData.getIssuerDN(), ocspCertificateData.getSerialNumber()
												,ERROR_NOTEXISTINGCALIMIT);
					    			} else {
										recheckList.add(new RecheckEntry(ocspCertificateData.getFingerprint(), ocspCertificateData.getUpdateTime(), i));
					    			}
								}
							}
						}
						ocspRowIndex++;
						caRowIndex++;
					}
				}
				currentFingerprint = certificateDataList.get(certificateDataList.size()-1).getFingerprint();
				recheckList = processRecheckList(recheckList, caEntityManager, ocspEntityManagers, ocspEntityManagerNames, inclusionMode, strictStatus, errorList, timeToConfirmError);
	    	}
	    	// Make sure we don't have any unhandled CertificateData at any of the OCSP responders left
			for (int i=0; i<ocspEntityManagers.size(); i++) {
		    	String ocspCurrentFingerprint = currentFingerprint;
				EntityManager ocspEntityManager = ocspEntityManagers.get(i);
				List<CertificateData> ocspCertificateDataList;
		    	while ( (ocspCertificateDataList = CertificateData.getNextBatch(ocspEntityManager, certificateProfileId,  ocspCurrentFingerprint, batchSize)) != null
		    			&& ocspCertificateDataList.size()>0) {
		    		for (CertificateData ocspCertificateData : ocspCertificateDataList) {
						// An update for this OCSP might have gone through since we read the CA database, re-check later
		    			if (ocspCertificateData.getUpdateTime() > new Date().getTime()+timeToConfirmError) {
							handleError(errorList, ocspEntityManagerNames.get(i), ocspCertificateData.getFingerprint(), ocspCertificateData.getIssuerDN(), ocspCertificateData.getSerialNumber()
									,ERROR_NOTEXISTINGCALIMIT);
		    			} else {
			    			recheckList.add(new RecheckEntry(ocspCertificateData.getFingerprint(), ocspCertificateData.getUpdateTime(), i));
		    			}
		    		}
					ocspCurrentFingerprint = ocspCertificateDataList.get(ocspCertificateDataList.size()-1).getFingerprint();
		    	}
			}
			// Process the re-check list until it's empty
			while (!recheckList.isEmpty()) {
				recheckList = processRecheckList(recheckList, caEntityManager, ocspEntityManagers, ocspEntityManagerNames, inclusionMode, strictStatus, errorList, timeToConfirmError);
				if (!recheckList.isEmpty()) {
					// Save the environment if there is nothing important to do.. =)
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						throw new RuntimeException(e);
					}
				}
			}
	    }
    	log.info("Whole operation took " + (new Date().getTime()-startTime)/1000 + " seconds.");
    	if (!errorList.isEmpty()) {
    		String errorReport = "Monitoring errors:\n";
    		for (String current : errorList) {
    			errorReport += current + "\n";
    			if (errorReport.length()>ERRORREPORT_SIZELIMIT) {
    				errorReport = errorReport.substring(0, ERRORREPORT_SIZELIMIT-4) + "...";
    			}
    		}
        	log.error(errorReport);
    	}
    	// Close all entity managers
    	for (EntityManager ocspEntityManager : ocspEntityManagers) {
    		ocspEntityManager.close();
    	}
    	caEntityManager.close();
    	return errorList.isEmpty() ? 0 : -1;

    }

    /**
     * Go through all items in recheckList and for those that a sufficient amount of time has passed, see if there still is a discrepancy.
     * @param recheckList
     * @param caEntityManager
     * @param ocspEntityManagers
     * @param ocspEntityManagerNames
     * @param inclusionMode
     * @param errorList
     * @return
     */
	private List<RecheckEntry> processRecheckList(List<RecheckEntry> recheckList, EntityManager caEntityManager, List<EntityManager> ocspEntityManagers, List<String> ocspEntityManagerNames, boolean inclusionMode, boolean strictStatus, List<String> errorList, long timeToConfirmError) {
		List<RecheckEntry> toKeep = new ArrayList<RecheckEntry>();
		for (RecheckEntry re : recheckList) {
			long now = new Date().getTime();
			if ( (now-re.updateTime) >= timeToConfirmError ) {
				CertificateData certificateData = CertificateData.findByFingerprint(caEntityManager, re.fingerprint);
				if (certificateData==null) {
					CertificateData ocspCertificateData = CertificateData.findByFingerprint(ocspEntityManagers.get(re.ocspEntityManagerIndex), re.fingerprint);
					handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), re.fingerprint, ocspCertificateData.getIssuerDN(), ocspCertificateData.getSerialNumber()
							,ERROR_NOTEXISTINGCA);
				} else if (certificateData.getUpdateTime() > re.updateTime) {
			    	if (log.isDebugEnabled()) {
						log.debug("A newer CertificateData with fingerprint "+certificateData.getFingerprint()+" exist in the CA database. Re-checking later it in list.");
			    	}
					re.updateTime = certificateData.getUpdateTime();
					toKeep.add(re);
				} else if (certificateData.getUpdateTime() < re.updateTime) {
					handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
							,ERROR_UPDATEDOCSP);
				} else {
					CertificateData ocspCertificateData = CertificateData.findByFingerprint(ocspEntityManagers.get(re.ocspEntityManagerIndex), re.fingerprint);
					if (ocspCertificateData == null) {
						handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
								,ERROR_NOTEXISTINGOCSP);
					} else if (ocspCertificateData.getUpdateTime() < certificateData.getUpdateTime()) {
						handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
								,ERROR_NOTUPDATED);
					} else if (ocspCertificateData.getUpdateTime() > certificateData.getUpdateTime()) {
						certificateData = CertificateData.findByFingerprint(caEntityManager, re.fingerprint);
						if (ocspCertificateData.getUpdateTime() <= certificateData.getUpdateTime()) {
							re.updateTime = certificateData.getUpdateTime();
							toKeep.add(re);
						} else {
							handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
									,ERROR_TAMPERED);
						}
					} else {
						if (certificateData.equals(ocspCertificateData, inclusionMode, strictStatus) ) {
					    	if (log.isDebugEnabled()) {
								log.debug("A CertificateData with fingerprint "+certificateData.getFingerprint()+" was found ok in OCSP database " + ocspEntityManagerNames.get(re.ocspEntityManagerIndex) + " after rechecking.");
					    	}
						} else {
							handleError(errorList, ocspEntityManagerNames.get(re.ocspEntityManagerIndex), certificateData.getFingerprint(), certificateData.getIssuerDN(), certificateData.getSerialNumber()
									,ERROR_TAMPERED);
						}
					}
				}
			} else {
				toKeep.add(re);
			}
		}
		return toKeep;
	}

	/**
	 * Add error message in a standardized format
	 * @param errorList the list to add this error-message to
	 * @param ocspName PU name as referenced in persistence.xml
	 * @param fingerprint the primary key for CertificateData
	 * @param issuerDN issuer of this certificate, since fingerprint isn't searchable in the GUI
	 * @param serialNumber serialNumber of this certificate, since fingerprint isn't searchable in the GUI
	 * @param message the reason why this entry made the error-list
	 */
	public void handleError(List<String> errorList, String ocspName, String fingerprint, String issuerDN, String serialNumber, String message) {
		serialNumber = new BigInteger(serialNumber).toString(16);	// Convert to hex String
		String errorMessage = "OCSP: " + ocspName + ", fingerprint: " + fingerprint + " issuerDN: \"" + issuerDN + "\", serialNumber: " + serialNumber
			+ " Message: " + message;
		log.error(errorMessage);
		if (errorList.size() < ERRORREPORT_LISTLIMIT) {
			errorList.add(errorMessage);
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Error list has already reached limit "+ERRORREPORT_LISTLIMIT+". Ignoring last entry.");
			}
			if (errorList.size() == ERRORREPORT_LISTLIMIT) {
				errorList.add("Additional errors are not available. Check log files.");
			}
		}
	}

	/**
	 * @return current memory usage for debugging
	 */
	private static long getUsedMemory() {
		return Runtime.getRuntime().totalMemory () - Runtime.getRuntime().freeMemory ();
	}

	/**
	 * Sufficient information to recheck the status of a certificate
	 */
    private class RecheckEntry {
		String fingerprint;
    	int ocspEntityManagerIndex;
    	long updateTime;

    	public RecheckEntry(String fingerprint, long updateTime, int ocspEntityManagerIndex) {
    		this.fingerprint = fingerprint;
    		this.updateTime = updateTime;
    		this.ocspEntityManagerIndex = ocspEntityManagerIndex;
		}
    }

}
