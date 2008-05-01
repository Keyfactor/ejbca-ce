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

import java.util.HashMap;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import net.sf.jasperreports.engine.JRException;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperExportManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/** Managed bean to be called from reports JSF pages
 * 
 * @author Original issuedCertificatesList method by MUNTEANU Olimpiu Andrei of Linagora
 * @version $Id$
 */
public class ReportsManagedBean extends BaseManagedBean {
	private static final Logger log = Logger.getLogger(ReportsManagedBean.class);

	public ReportsManagedBean() {
	}
	
	public String issuedCertificatesList() throws Exception {
		return doReport("certificatelist.jrxml");
	}
	
	public String doReport(String reportfile) throws Exception {
	    // setting up some basic stuff
		// This is not so pretty, I would much rather like not to pull web beans into here, 
		// but you know...
		EjbcaWebBean ejbcawebbean = getEjbcaWebBean();
		FacesContext context = FacesContext.getCurrentInstance();
		ExternalContext ectx = context.getExternalContext();
		HttpServletRequest req = (HttpServletRequest)ectx.getRequest();
		ServletContext servletContext = req.getSession().getServletContext();
		RAInterfaceBean rabean = new RAInterfaceBean();
		rabean.initialize(req, ejbcawebbean);

		// Report texts
		String report_title = ejbcawebbean.getText("CERTIFICATES_REPORT_TITLE");
		String report_revoked = ejbcawebbean.getText("CERTIFICATES_REPORT_REVOKED");
		String report_ok = ejbcawebbean.getText("CERTIFICATES_REPORT_OK");
		String report_description = ejbcawebbean.getText("CERTIFICATES_REPORT_DESCRIPTION");
		String report_issuer = ejbcawebbean.getText("CERTIFICATES_REPORT_ISSUER");
		String report_subject = ejbcawebbean.getText("CERTIFICATES_REPORT_SUBJECT");
		String report_revocation_date = ejbcawebbean.getText("CERTIFICATES_REPORT_REVOCATION_DATE");
		String report_total_number = ejbcawebbean.getText("CERTIFICATES_REPORT_TOTAL_NUMBER");
		String report_user_name = ejbcawebbean.getText("CERTIFICATES_REPORT_USER_NAME");
		String report_ca = ejbcawebbean.getText("CA");

		//HashMap<String, String> hashMap = new HashMap<String, String>();
		HashMap hashMap = new HashMap();
		hashMap.put("title", report_title);
		hashMap.put("revoked", report_revoked);
		hashMap.put("ok", report_ok);
		hashMap.put("description", report_description);
		hashMap.put("issuer", report_issuer);
		hashMap.put("subject", report_subject);
		hashMap.put("revocation_date", report_revocation_date);
		hashMap.put("total_number", report_total_number);
		hashMap.put("userName", report_user_name);
		hashMap.put("ca", report_ca);

	    String reportFilename = null;

		try {
			String jrxmlPath = servletContext.getRealPath("/WEB-INF/reports/");
		    // directories where the report files are 
			String jrxmlfile = jrxmlPath+"/"+reportfile;
			log.debug("Reading reports definition file: "+jrxmlfile);
			//InputStream is = this.getClass().getClassLoader().getResourceAsStream("/WEB-INF/reports/"+jrxmlfile);
			JasperReport jasperReport = JasperCompileManager.compileReport(jrxmlfile);
			//is.close();
			log.debug("Compiled report: "+jasperReport.getName());
			

			// we use the ReportsCharts class as data source 
			// instead of connecting directly to the database
			ReportsDataSource logCharts = new ReportsDataSource(rabean);
			JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, hashMap, logCharts);
			log.debug("Filled report: "+jasperPrint.getName());

			// and directories where the reports will be generated
			String reportsPath = servletContext.getRealPath("/reports/");
			reportFilename =  "reports_" + req.getSession().getId() + ".html";
			String reportFile = reportsPath +"/"+reportFilename;
			log.debug("Will write report to file: "+reportFile);

			JasperExportManager.exportReportToHtmlFile(jasperPrint, reportFile);
		} catch (JRException e) {
			log.error(e); 
			log.error(e.getCause()); 
		} 
		// Redirect user browser to the report page
		String redirect_file = "/reports/" + reportFilename;
		//String redirect_page = "/ejbca/adminweb" + redirect_file;
		log.debug("Redirecting to: "+redirect_file);
		ectx.dispatch(redirect_file);
		context.responseComplete();		
		return null;
	}
	
	public String revokedCertificatesPie() throws Exception {
		return doReport("revokedcertschart.jrxml");
	}
}
