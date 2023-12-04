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

package org.ejbca.util.mail;

import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.log4j.Logger;
import org.ejbca.config.MailConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ServiceLocatorException;

/**
 * Simple wrapper for JavaMail.
 * 
 * @version $Id$
 */
public class MailSender {
	
	private static final Logger log = Logger.getLogger(MailSender.class);

	private static final int TIMEOUT_PERIOD = 15000;
	
	// Some constants to make it easier to read the client code
	public final static List<String> NO_TO = null;	//List<String>
	public final static List<String> NO_CC = null;	//List<String>
	public final static List<MailAttachment> NO_ATTACHMENTS = null;	//List<MailAttachment>
	
	/**
	 * Returns true if mail is configured and available in the application server.
	 */
	public static boolean isMailConfigured() {
	    try {
	        ServiceLocator.getInstance().getMailSession(MailConfiguration.getMailJndiName());
	        return true;
        } catch (ServiceLocatorException e) {
            return false;
        } catch (RuntimeException e) {
            log.debug("Caught runtime exception when checking for presence of mail session", e);
            return false;
        }
	}

	/**
	 * Helper method for sending mail using the mail service configured in mail.properties.
	 * 
	 * @param fromAddress The "From" address
	 * @param toList List<String> of addresses that will end up in the "To"-field or null to disable
	 * @param ccList List<String> of addresses that will end up in the "Cc"-field or null to disable
	 * @param subject The email subject
	 * @param content The text message body
	 * @param attachments List<MailAttachment> of files and objects to attach to the email or null to disable multipart messages
	 * @throws MailException if the message could not be successfully handed over to JavaMail
	 */
	public static void sendMailOrThrow(String fromAddress, List<String> toList, List<String> ccList, String subject, String content, List<MailAttachment> attachments) throws MailException {
	    try {
            final Session mailSession = ServiceLocator.getInstance().getMailSession(MailConfiguration.getMailJndiName());
            if (!sendMailWithSession(mailSession, fromAddress, toList, ccList, subject, content, attachments)) {
                throw new MailException("Failed to hand over email to JavaMail.");
            }
        } catch (ServiceLocatorException e) {
            final String msg = "E-mail is not available in the application server: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.error(msg, e);
            } else {
                log.error(msg);
            }
            throw new MailException(msg, e);
        }
	}

	/**
	 * Helper method for sending mail using the mail service configured in mail.properties.
	 * 
	 * @param fromAddress The "From" address
	 * @param toList List<String> of addresses that will end up in the "To"-field or null to disable
	 * @param ccList List<String> of addresses that will end up in the "Cc"-field or null to disable
	 * @param subject The email subject
	 * @param content The text message body
	 * @param attachments List<MailAttachment> of files and objects to attach to the email or null to disable multipart messages
	 * @return true if the message was successfully handed over to JavaMail
	 */
	public static boolean sendMail(String fromAddress, List<String> toList, List<String> ccList, String subject, String content, List<MailAttachment> attachments) {
        try {
            final Session mailSession = ServiceLocator.getInstance().getMailSession(MailConfiguration.getMailJndiName());
            return sendMailWithSession(mailSession, fromAddress, toList, ccList, subject, content, attachments);
        } catch (ServiceLocatorException e) {
            throw new IllegalStateException(e);
        }
	}

    private static boolean sendMailWithSession(final Session mailSession, String fromAddress, List<String> toList, List<String> ccList, String subject, String content, List<MailAttachment> attachments) {
        // It would be good if we could set mail session properties, but it seems not possible
        // See https://javamail.java.net/nonav/docs/api/com/sun/mail/smtp/package-summary.html
        // mail.smtp.timeout
        // mail.smtp.connectiontimeout
        // mail.smtp.writetimeout
		mailSession.getProperties().put("mail.smtp.timeout", TIMEOUT_PERIOD);
		mailSession.getProperties().put("mail.smtp.connectiontimeout", TIMEOUT_PERIOD);
		mailSession.getProperties().put("mail.smtps.connectiontimeout", TIMEOUT_PERIOD);
        Message msg = new MimeMessage(mailSession);
        try {
        	if (log.isDebugEnabled()) {
        		log.debug("from: " + fromAddress);
        	}
			msg.setFrom(new InternetAddress(fromAddress));
			boolean atLeastOneRecipient = false;
			if (toList != null) {
				for (int i=0; i<toList.size(); i++) {
					String to = toList.get(i);
					msg.addRecipients(javax.mail.Message.RecipientType.TO, InternetAddress.parse(to, false));
		        	if (log.isDebugEnabled()) {
		        		log.debug("to: " + to);
		        	}
					atLeastOneRecipient = true;
				}
			}
			if (ccList != null) {
				for (int i=0; i<ccList.size(); i++) {
					String cc = ccList.get(i);
					msg.addRecipients(javax.mail.Message.RecipientType.CC, InternetAddress.parse(cc, false));
		        	if (log.isDebugEnabled()) {
		        		log.debug("cc: " + cc);
		        	}
					atLeastOneRecipient = true;
				}
			}
			if (!atLeastOneRecipient) {
			    log.info("Missing e-mail recipient");
				return false;	// We need at least one recipient.. either TO or CC
			}
	        msg.setSubject(subject);
        	if (log.isDebugEnabled()) {
        		log.debug("subject: " + subject);
        	}
	        if (attachments == null || attachments.size() == 0) {
		        msg.setContent(content, MailConfiguration.getMailMimeType());
	        	if (log.isDebugEnabled()) {
	        		log.debug("content: " + content);
	        	}
	        } else {
		        Multipart multipart = new MimeMultipart();
		        // Add the text message first
		        MimeBodyPart msgBody = new MimeBodyPart();
		        msgBody.setContent(content, MailConfiguration.getMailMimeType());
		        multipart.addBodyPart(msgBody);
		        // Attach all the requested files
                for (MailAttachment mailAttachment : attachments) {
                    MimeBodyPart msgAttachment = new MimeBodyPart();
                    msgAttachment.setDataHandler(mailAttachment.getDataHandler());
                    msgAttachment.setFileName(mailAttachment.getName());
                    multipart.addBodyPart(msgAttachment);
                }
		        msg.setContent(multipart);
	        }
	        msg.setHeader("X-Mailer", "JavaMailer");
	        msg.setSentDate(new Date());
			Executors.newSingleThreadExecutor().submit(() -> {
				try {
					Transport.send(msg);
					log.info("Sending email is successful.");
				} catch (MessagingException e) {
					log.error("Unable to send email: ", e);
				}
			});

		} catch (MessagingException e) {
			log.error("Unable to send email: ", e);
			return false;
		}
        return true;
	}
}
