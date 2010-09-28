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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateData;

/**
 * Simple and dirty tool for moving database tables from one database to another.
 * 
 * The main reason for creating this tool was to test OcspMonitoringTool working
 * on two different database types at the same time.
 * 
 * @version $Id$
 */
public class DatabaseCopyTool extends ClientToolBox {

	private static final Logger log = Logger.getLogger(DatabaseCopyTool.class);
	
	final String usage = "\n"
		+ getName() + " <dbName1> <dbName2> <tableName1> [<tableName2>]\n"
		+ " This commands relies on a JPA properties/META-INF/persistence.xml being present and configured for your environment.\n"
		+ " JDBC drivers used in persistence.xml also has to present in lib/.\n\n"
		+ " ** This tool should only be run with offline databases that are upgraded to the latest version. **\n\n"
		+ " dbName1:    persistence-unit name of source database in the persistence.xml file\n"
		+ " dbName2:    persistence-unit name of target database in the persistence.xml file.\n"
		+ " tableName1: only CertificateData is currently supported\n";


    /**
     * @param args command line arguments
     */
    public static void main(String[] args) {
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add("dummy");
        for ( int i=0; i<args.length; i++) { // remove first argument
            lArgs.add(args[i]);
        }
        new DatabaseCopyTool().execute(lArgs.toArray(new String[]{}));
    }
    
    /*
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
	@Override
	public String getName() {
        return "DBCOPY";
	}

	/*
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    public void execute(String[] args) {
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
    	log.info("Database copy tool started.");
    	long startTime = new Date().getTime();
    	// Parse arguments and setup entityManagers
    	if (args.length<4) {
    		log.info(usage);
    		return -1;
    	}
		EntityManager sourceEntityManager = Persistence.createEntityManagerFactory(args[1]).createEntityManager();
		EntityManager targetEntityManager = Persistence.createEntityManagerFactory(args[2]).createEntityManager();
    	List<String> tableList = new ArrayList<String>();
    	for (int i=3; i<args.length; i++) {
    		tableList.add(args[i]);
    	}
    	for (String tableName : tableList) {
    		if (tableName.equalsIgnoreCase("CertificateData")) {
    			copyCertificateData(sourceEntityManager, targetEntityManager);
    		} else {
    			// Not a supported table
        		log.info(usage);
        		return -1;
    		}
    	}
    	log.info("Whole operation took " + (new Date().getTime()-startTime)/1000 + " seconds.");
    	return 0;
    }

    /**
     * Copy CertificateData table
     */
	private void copyCertificateData(EntityManager sourceEntityManager, EntityManager targetEntityManager) {
    	long totalEntries = CertificateData.getCount(sourceEntityManager);
    	long count = 0;
		int batchSize = 100;
		String currentFingerprint = "0";
		while (true) {
			// Fetch batch of rows from source
			List<CertificateData> sourceList = CertificateData.getNextBatch(sourceEntityManager, currentFingerprint, batchSize);
			if (sourceList.size()==0) {
				break;
			}
			sourceEntityManager.clear();	// Detach
			log.info("Got " + sourceList.size() + " rows starting with " + count + " of " + totalEntries + ".");
			count += sourceList.size();
			// Write batch of rows to target
			targetEntityManager.getTransaction().begin();
			for (CertificateData certificateData : sourceList) {
				targetEntityManager.persist(certificateData);
			}
			targetEntityManager.getTransaction().commit();
			currentFingerprint = sourceList.get(sourceList.size()-1).getFingerprint();
		}
		
	}
    

}
