package org.ejbca.config;

public class MailConfiguration {

	/**
	 * The JNDI-name used to send email notifications from EJBCA.
	 */
	public static String getMailJndiName() {
		return ConfigurationHolder.getExpandedString("mail.jndi-name", "java:/EjbcaMail");
	}

}
