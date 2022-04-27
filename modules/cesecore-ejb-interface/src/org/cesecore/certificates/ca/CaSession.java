/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

/*! \mainpage The CESeCore project
*
* \section section1 Heading towards Common Criteria certification
*
* In order to make the CESeCore security core publicly available for
* integration in numerous security based applications, the CESeCore
* project aims to realize a CESeCore Common Criteria EAL4+
* certification.
*
* \section section2 Reusable Java library
*
* Taking on the form of a common security function Java library, the
* CESeCore security core will provide a reusable base for implementing
* third-party trustworthy systems. The ready-made CESeCore library
* simplifies development of secure software, and allows for Common
* Criteria certification to be easily extended to any related product
* or service.
*
* \section section3 Integrator friendly
*
* CESeCore integrators will be able to correct, improve and extend their
* applications at any time - without the need to perform frequent system
* re-evaluations, nor perform continous checks of the security functions
* implemented by the security core (including features like digital
signature
* creation/validation, digital certificate and CRLs creation, key management
* and maintenance of a secure audit log).
*/

/**
 * CRUD bean for creating, removing and retrieving CAs.
 */
public interface CaSession {

    /** Adds a CA to the database 
     * 
     * @param admin AuthenticationToken of admin
     * @param ca the CA to add
     * @throws CAExistsException if CA already exists
     * @throws AuthorizationDeniedException if not authorized to add CA
     */
     void addCA(AuthenticationToken admin, CACommon ca) throws CAExistsException, AuthorizationDeniedException;
    
    /** Changes a CA in the database. Can change mostly everything except caid, caname and subject DN. When editing a CA the CA token will usually be taken off line.
     * So you need to activate the CA token after editing, if auto-activation of the CA token is not enabled. 
     * 
     * There's also CAAdminSession.editCA() which handles some special cases, e.g. changing the Subject DN of
     * uninitialized CAs.
     * 
     * @param admin AuthenticationToken of admin
     * @param cainfo the CAInfo to change values of the CA
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws InternalKeyBindingNonceConflictException 
     * @throws CaMsCompatibilityIrreversibleException
     */
    void editCA(final AuthenticationToken admin, final CAInfo cainfo) throws CADoesntExistsException, AuthorizationDeniedException, InternalKeyBindingNonceConflictException, CaMsCompatibilityIrreversibleException;

    /**
     * Method returning id's of all CA's in system.
     * 
     * @return a List (Integer) of CA id's
     */
    List<Integer> getAllCaIds();

    /**
     * Method returning id's of all CA's available to the system that the
     * administrator is authorized to, 
     * 
     * Does not log access control to all CAs it checks, because this does not 
     * give access to the CAs but only returns IDs of CAs.
     * 
     * @param admin AuthenticationToken of admin
     * @return a List<Integer> of available CA IDs
     */
     List<Integer> getAuthorizedCaIds(AuthenticationToken admin);
     
     /**
      * Method returning names of all CA's available to the system that the
      * administrator is authorized to, 
      * 
      * Does not log access control to all CAs it checks, because this does not 
      * give access to the CAs but only returns names of CAs.
      * 
      * @param admin AuthenticationToken of admin
      * @return a Collection<String> of available CA names
      */
     Collection<String> getAuthorizedCaNames(AuthenticationToken admin);
     
     /**
      * Like {@link #getAuthorizedCaNames(AuthenticationToken)}, but returns a TreeMap which includes the CA Id as well.
      * @param admin AuthenticationToken of admin
      * @return a Collection<String> of available CA names
      * @see #getAuthorizedCaNames
      */
     TreeMap<String,Integer> getAuthorizedCaNamesToIds(AuthenticationToken admin);
     
     /**
      * Method returning info objects for all CA's available to the system that the administrator is authorized to. 
      * 
      * Does not log access control to all CAs it checks, because this does not 
      * give access to the CAs but only returns CAInfo of CAs.
      * 
      * @param authenticationToken AuthenticationToken of admin
      * @return a List<CAInfo> of authorized CAs
      */
     List<CAInfo> getAuthorizedCaInfos(AuthenticationToken authenticationToken);

     /**
      * Method returning info objects for  all active CA's available to the system, i.e. not 
      * having status "external", uninitialized or "waiting for certificate response" and that the
      * administrator is authorized to, 
      * 
      * Does not log access control to all CAs it checks, because this does not 
      * give access to the CAs but only returns CAInfo of CAs.
      * 
      * @param authenticationToken AuthenticationToken of admin
      * @return a List<CAInfo> of authorized and enabled CAs
      */
     List<CAInfo> getAuthorizedAndEnabledCaInfos(AuthenticationToken authenticationToken);
     
     /**
      * Method returning info objects for all non-external CA's available to the system, i.e. not 
      * having status "external", and that the administrator is authorized to. 
      * 
      * Does not log access control to all CAs it checks, because this does not 
      * give access to the CAs but only returns CAInfo of CAs.
      * 
      * @param authenticationToken AuthenticationToken of admin
      * @return a List<CAInfo> of authorized and non-external CAs
      */
     List<CAInfo> getAuthorizedAndNonExternalCaInfos(AuthenticationToken authenticationToken);
     
    /**
     * Method returning names of all CA's available to the system that the
     * administrator is authorized to i.e. not having status "external" or
     * "waiting for certificate response"
     * 
     * @param admin AuthenticationToken of admin
     * @return a List<String> of available CA names
     */
    List<String> getActiveCANames(final AuthenticationToken admin);

    /**
     * Returns a value object containing non-sensitive information about a CA
     * give it's name.
     * 
     * @param admin administrator calling the method
     * @param name human readable name of CA
     * @return CAInfo value object, null if it doesn't exist
     * @throws AuthorizationDeniedException if admin not authorized to CA 
     */
    CAInfo getCAInfo(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Returns a value object containing non-sensitive information about a CA
     * give it's name.
     * 
     * @param admin administrator calling the method
     * @param caid numerical unique id of CA
     * @return CAInfo value object, null if it doesn't exist
     * @throws AuthorizationDeniedException if admin not authorized to CA 
     */
    CAInfo getCAInfo(AuthenticationToken admin, int caid) throws  AuthorizationDeniedException;

    /**
     * Fetches the current certificate chain for a CA.
     *
     * <pre>
     * <b>Authorization requirements:</b>
     * - /administrator
     * - /ca/&lt;ca in question&gt;
     * </pre>
     *
     * @param caName the unique name of the CA whose certificate chain should be returned.
     * @return a list of X509 Certificates or CVC Certificates with the root certificate last, or an empty list if the CA's status is "Waiting for certificate response".
     * @throws AuthorizationDeniedException if the client does not fulfill the authorization requirements specified above.
     * @throws CADoesntExistsException if the CA with the CA name given as input does not exist.
     */
    Collection<CertificateWrapper> getCaChain(AuthenticationToken authenticationToken, String caName)
            throws AuthorizationDeniedException, CADoesntExistsException;
    
    /**
     * Method used to remove a CA from the system. You should first check that
     * the CA isn't used by any EndEntity, Profile or AccessRule before it is
     * removed. CADataHandler for example makes this check. 
     * Should be used with care. If any certificate has been created with the CA use revokeCA
     * instead and don't remove it.
     * 
     * @param admin AuthenticationToken of admin
     * @param caid numerical unique id of CA
     * 
     * If the CA does not exist, nothing happens the method return silently.
     * @throws AuthorizationDeniedException if not authorized to remove CA
     */
    void removeCA(AuthenticationToken admin, int caid) throws AuthorizationDeniedException;

    /**
     * Renames the short name of CA (used in administrators interfaces). 
     * This name does not have to be the same as SubjectDN and is only used for reference.
     * 
     * @param admin AuthenticationToken of admin
     * @param oldname the name of the CA to rename
     * @param newname the new name of the CA
     * 
     * @throws CAExistsException if the CA with newname already exists
     * @throws CADoesntExistsException if the CA with oldname does not exist
     * @throws AuthorizationDeniedException if not authorized to rename CA
     */
    void renameCA(AuthenticationToken admin, String oldname, String newname) throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Check if a CA with given ID exists
     * 
     * @param caId the CA ID
     * @return true if a CA with the given ID exists
     */
    boolean existsCa(int caId);

    /**
     * Check if a CA with given name exists
     * 
     * @param name the CA name
     * @return true if a CA with the given name exists
     */
    boolean existsCa(String name);

    /**
     * Returns the future key/certificate rollover if a rollover is pending, or otherwise null.
     * @param caid numerical unique id of CA
     * @throws CADoesntExistsException If no CA with the given CA Id exists.
     */
    Certificate getFutureRolloverCertificate(int caid) throws CADoesntExistsException;

    /**
     * Determines which CRL Partition Index a given certificate belongs to. This check is based on the URI in the Issuing Distribution Point extension.
     * @param caId the CA ID
     * @param cert Certificate to check
     * @return Partition index, or zero if not using partitioning.
     */
    int determineCrlPartitionIndex(int caId, CertificateWrapper cert);

    /**
     * Find the CA on the this instance who issued the given certificate, using the
     * <code>authorityKeyIdentifier</code> in the certificate.
     *
     * @param authenticationToken an authentication token.
     * @param certificate The certificate whose issuer should be retrieved.
     * @return an optional containing the CA or an empty optional if
     * the CA could not be found or if the authentication token is not authorised to read it.
     */
    Optional<CAInfo> getIssuerFor(AuthenticationToken authenticationToken, X509Certificate certificate);
}
