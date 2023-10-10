package org.cesecore.certificates.certificate;

import javax.ejb.Remote;

/**
 * The interface for internal functionality, needed for the CA performance, used by CLI.
 * As an example the count of the total or active certificates etc.
 */
@Remote
public interface InternalCertificateSessionRemote extends InternalCertificateSession {
}
