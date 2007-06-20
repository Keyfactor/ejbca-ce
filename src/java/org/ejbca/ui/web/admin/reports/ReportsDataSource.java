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

package org.ejbca.ui.web.admin.reports;

import java.util.Date;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRException;
import net.sf.jasperreports.engine.JRField;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.rainterface.CertificateView;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.UserView;

/**
 * ReportsDataSource is a class used as DataSource for JasperReports
 * 
 * it wraps data from ejbca beans and converts them in real time
 * to ready to use data flow for the jasperreports engine
 * 
 * this class is required only when jasperreports is not alowed 
 * to read the MySQL database directly (it shouldn't do that)
 * 
 * @author  Original author is MUNTEANU Olimpiu Andrei of Linagora
 * @version $Id: ReportsDataSource.java,v 1.2 2007-06-20 11:54:02 anatom Exp $
 */
public class ReportsDataSource implements JRDataSource {

	private static final Logger log = Logger.getLogger(ReportsDataSource.class);
	
	private RAInterfaceBean rabean = null;
	
	//variables that represent information about
	//one line in the report at a time
	private String issuerDN = "";
	private String subjectDN = "";
	private String userName = "";
	private boolean isRevoked = true;
	private Date revocationDate = null;
	private String ca = "";

	//internal variable used to iterate all the users at demand
	//(when jasperreports ask for more information)
	private UserView[] users = null;
	private int record = 0;
	//how many results to print (-1 for all)
	private int size = -1; //-1 means unlimited

	//i is used to iterate users. At a given time it 
	//points to current user in users variable
	private int i = 0;
	//j is used to iterate certificates of each user...
	private int j = 0;
	
	//total number of certificates for the current user
	private int number = 0;

	
	//used as a state for the class
	//when there is no more information, theEnd == true
	private boolean theEnd = false;
	//used to trick jasperreports and to create at least one fake linein the report
	//my report does not like empty reports (don't know why yet)
	private boolean empty = true;
	private boolean fake = false;

	//the current user (the same as that witch i variable points to in users)
	private UserView user = null; 

	/*
	 * constructor
	 */
	public ReportsDataSource(RAInterfaceBean _rabean) 
	{
		rabean = _rabean;
		
		theEnd = false;
		empty = true;
		fake = false;

        issuerDN = "";
		subjectDN = "";
		userName = "";
		isRevoked = true;
		revocationDate = null;
		ca = "";

		record = 0;
		size = -1; //-1 means unlimited

		try {
    		users = rabean.findAllUsers(record, size);
		} catch (Exception e) {
			log.error(e); 
		}

		i = -1;
		
	}

	/*
	 * go to next user
	 * and then to his first certificate
	 */
	private void newI() 
	{
		i++;
		if (i >= users.length) 
		{
			theEnd = true;
		} 
		else 
		{
			user = users[i];

			try {
				rabean.loadCertificates(user.getUsername());
			} catch (Exception e) {
				log.error(e); 
			}

			number = rabean.getNumberOfCertificates();
			
			j = -1;newJ();
		}
		
	}

	/*
	 * go to next certificate of the current user
	 * and to the next user if there is no certificate left for this user
	 */
	private void newJ() 
	{
		j++;
		if (j >= number)
		{
			newI();
		} 
		else 
		{
			CertificateView cv = rabean.getCertificate(j);
			userName = cv.getUsername();
			issuerDN = cv.getIssuerDN();
			subjectDN = cv.getSubjectDN();
			isRevoked = cv.isRevoked();
			revocationDate = cv.getRevokationDate();
			ca = user.getCAName();

			/*
			 * complicated.... used to extract more information about the certificate ????
			 * 
			 * int subjectfieldsize = viewendentityhelper.profile.getSubjectDNFieldOrderLength();
		     * for(int i = 0; i < subjectfieldsize; i++)
		     * {
		     *   	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectDNFieldsInOrder(i);
		     *   	 viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectDNField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
			 *
             * }
             */
			
		}
	}

	/*
	 * used only when there is no line in the report (no certificate visible)
	 * it is used to generate a fake line because some reports does not like empty data sources
	 */
	private Object getFakeFieldValue(JRField jrf) throws JRException 
	{
		if (jrf.getName().equals("userName")) 
		{
			return "Fake User";
		}
		else if (jrf.getName().equals("ca"))
		{
			return "_";
		}		
		else if (jrf.getName().equals("issuerDN"))
		{
			return "_";
		}
		else if (jrf.getName().equals("subjectDN"))
		{
			return "You don't have certificates";
		}		
		else if (jrf.getName().equals("isRevoked"))
		{
			return false;
		}		
		else if (jrf.getName().equals("revocationDate"))
		{
			return 0l;
		}
		return null;
	}

	/*
	 * this function is called by jasperreports every time
	 * it neads information about a single parameter in the current line
	 * of the report it is about to generate
	 * 
	 * usually, for each line of the report, jasperreports calls this function
	 * once for each parameter. 
	 * 
	 * in this report, we use only 4: 
	 *  - userName is the first column of the report
	 *  - ca seccond column
	 *  - subjectDN third column
	 *  - revocationDate last column
	 */
	public Object getFieldValue(JRField jrf) throws JRException 
	{
		if (fake) 
		{
			return getFakeFieldValue(jrf);
		}
		
		if (jrf.getName().equals("userName")) 
		{
			return userName;
		}
		else if (jrf.getName().equals("ca"))
		{
			return ca;
		}		
		else if (jrf.getName().equals("issuerDN"))
		{
			return issuerDN;
		}		
		else if (jrf.getName().equals("subjectDN"))
		{
			return subjectDN;
		}		
		else if (jrf.getName().equals("isRevoked"))
		{
			return isRevoked;
		}		
		else if (jrf.getName().equals("revocationDate"))
		{
			return revocationDate.getTime();
		}
		return null;
	}

	/*
	 * this funtion is called by jasperreports each time
	 * it has finished generating a line of the report
	 * 
	 * it then calls this function so that LogCharts can 
	 * go to the next line
	 * 
	 * the returned value is true if there is a next line
	 * the returned value is false if we passed the end of the report
	 */
	public boolean next() throws JRException 
	{
		if (i == -1) 
		{
			newI();
		} 
		else 
		{
			newJ();
		}

		if (empty && theEnd) 
		{
			empty = false;
			fake = true;
			return true;
		}
		
		empty = false;
		
		return (!theEnd);
	}

}
