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
package org.ejbca.ui.cli;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ValueExtractor;
import org.ejbca.core.ejb.log.LogEntryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;

/**
 * Small CLI to export the audit log from EJBCA 4.0 and earlier to a simple text file.
 *  
 * @version $Id$
 */
//Suppress warnings for deprecation of the Admin and LogEntryData objects, required for legacy support
@SuppressWarnings("deprecation")
public class OldLogExportCli {

	private static final Logger LOG = Logger.getLogger(OldLogExportCli.class);

	//TODO: create .sh and .bat, additional orm-mappings.. more comments, test with huge log-table
	public static void main(final String[] args) throws IOException {
		final String USAGE = "\n"
			+ "java -Djava.endorsed.dirs=<jdbc-driver dir> -jar oldlogexport-cli.jar <exportfile> [<batch size>]\n"
			+ " jdbc-driver dir: directory where the JDBC driver JAR is located\n"
			+ " exportfile:      persistence-unit name of source database in the persistence.xml file\n"
			+ " batch size:      number of rows to process in each batch. Default is 10000.";
		if (args.length<1) {
			LOG.info(USAGE);
			return;
		}
		int batchSize = 10000;
		if (args.length==2) {
			try {
				batchSize = Integer.parseInt(args[1]);
			} catch (NumberFormatException e) {
				LOG.info(args[1] + " is not a valid number.");
				return;
			}
		}
		new OldLogExportCli().run(args[0], batchSize);
	}

	private void run(final String filename, final int batchSize) throws UnsupportedEncodingException, IOException {
		LOG.info("Started export..");
		final long startTime = System.currentTimeMillis();
		final OutputStream os = new FileOutputStream(filename);
		writeHeader(os);
		final EntityManager entityManager = Persistence.createEntityManagerFactory("oldlogexport").createEntityManager();
		LOG.info(" Fetching number of total log entries..");
		final int total = getCount(entityManager);
		LOG.info("  ..found " + total + " log entries in database.");
		int resultPosition = 0;
		while (true) {
			final List<LogEntryData> batch = getNextBatch(entityManager, resultPosition, batchSize);
			if (batch.size()==0) {
				break;
			}
			LOG.info(" Fetching batch from position " + resultPosition + ". Current batch size is " + batch.size() + ".");
			exportBatch(os, batch);
			resultPosition += batch.size();
		}
		os.close();
		LOG.info("Finished export in " + (System.currentTimeMillis()-startTime)/1000 + " seconds.");
	}

	@SuppressWarnings("unchecked")
	private List<LogEntryData> getNextBatch(final EntityManager entityManager, final int first, final int max) {
		return entityManager.createQuery("SELECT a FROM LogEntryData a ORDER BY a.id ASC").setFirstResult(first).setMaxResults(max).getResultList();
	}

	private int getCount(final EntityManager entityManager) {
		return ValueExtractor.extractIntValue(QueryResultWrapper.getSingleResult(entityManager.createQuery("SELECT COUNT(a) FROM LogEntryData a")));
	}

	private void writeHeader(final OutputStream os) throws UnsupportedEncodingException, IOException {
		final StringBuilder sb = new StringBuilder();
		sb.append("id").append(';');
		sb.append("time").append(';');
		sb.append("module").append(';');
		sb.append("event").append(';');
		sb.append("caId").append(';');
		sb.append("adminType").append(';');
		sb.append("adminData").append(';');
		sb.append("username").append(';');
		sb.append("certificate").append(';');
		sb.append("comment").append('\n');
		os.write(sb.toString().getBytes("UTF-8"));
	}

	private void exportBatch(final OutputStream os, final List<LogEntryData> batch) throws UnsupportedEncodingException, IOException {
		final StringBuilder sb = new StringBuilder();
		for (final LogEntryData logEntryData : batch) {
			final LogEntry logEntry = logEntryData.getLogEntry();
			sb.append(String.valueOf(logEntry.getId())).append(';');
			sb.append(ValidityDate.formatAsISO8601(logEntry.getTime(), ValidityDate.TIMEZONE_UTC)).append(';');
			sb.append(LogConstants.MODULETEXTS[logEntry.getModule()]).append(';');
			sb.append(logEntry.getEventName()).append(';');
			sb.append(String.valueOf(logEntry.getCAId())).append(';');
			sb.append(Admin.ADMINTYPETEXTS[logEntry.getAdminType()]).append(';');
			sb.append(logEntry.getAdminData()).append(';');
			sb.append(logEntry.getUsername()).append(';');
			sb.append(logEntry.getCertificateSNR()).append(';');
			sb.append(logEntry.getComment()).append('\n');
		}
		os.write(sb.toString().getBytes("UTF-8"));
	}
}
