package se.anatom.ejbca.webdist.hardtokeninterface;

import se.anatom.ejbca.hardtoken.*;
import se.anatom.ejbca.log.*;
import se.anatom.ejbca.ra.authorization.AdminInformation;
import se.anatom.ejbca.util.StringTools;

import java.math.BigInteger;

import java.rmi.RemoteException;

import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.Iterator;
import java.util.TreeMap;

import javax.naming.*;

import javax.servlet.http.HttpServletRequest;


/**
 * A java bean handling the interface between EJBCA hard token module and JSP pages.
 *
 * @author Philip Vendil
 * @version $Id: LogInterfaceBean.java,v 1.13 2002/08/28 12:22:25 herrvendil Exp $
 */
public class HardTokenInterfaceBean {
    /**
     * Creates new LogInterfaceBean
     */
    public HardTokenInterfaceBean() {
    }

    // Public methods.

    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request)
        throws Exception {
        if (!initialized) {
            admininformation = new AdminInformation(((X509Certificate[]) request.getAttribute(
                        "javax.servlet.request.X509Certificate"))[0]);
            admin = new Admin(((X509Certificate[]) request.getAttribute(
                        "javax.servlet.request.X509Certificate"))[0]);

            InitialContext jndicontext = new InitialContext();
            IHardTokenSessionHome hardtokensessionhome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "HardTokenSession"), IHardTokenSessionHome.class);
            hardtokensession = hardtokensessionhome.create();

            IHardTokenBatchJobSessionHome hardtokenbatchsessionhome = (IHardTokenBatchJobSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "HardTokenBatchJobSession"), IHardTokenBatchJobSessionHome.class);
            hardtokenbatchsession = hardtokenbatchsessionhome.create();

            availablehardtokens = hardtokensession.getAvailableHardTokens();
            initialized = true;
        }
    }

    /* Returns the first found hard token for the given username. */
    public HardTokenView getHardTokenViewWithUsername(String username)
        throws RemoteException {
        HardTokenView returnval = null;

        this.result = null;

        Collection res = hardtokensession.getHardTokens(admin, username);
        Iterator iter = res.iterator();

        if (res.size() > 0) {
            this.result = new HardTokenView[res.size()];

            for (int i = 0; iter.hasNext(); i++) {
                this.result[i] = new HardTokenView(availablehardtokens, (HardTokenData) iter.next());
            }
        } else {
            this.result = null;
        }

        if ((this.result != null) && (this.result.length > 0)) {
            return this.result[0];
        } else {
            return null;
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public HardTokenView getHardTokenViewWithIndex(String username, int index)
        throws RemoteException {
        HardTokenView returnval = null;

        if (result == null) {
            getHardTokenViewWithUsername(username);
        }

        if (result != null) {
            if (index < result.length) {
                returnval = result[index];
            }
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getHardTokensInCache() {
        int returnval = 0;

        if (result != null) {
            returnval = result.length;
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public HardTokenView getHardTokenView(String tokensn)
        throws RemoteException {
        HardTokenView returnval = null;
        this.result = null;

        HardTokenData token = hardtokensession.getHardToken(admin, tokensn);

        if (token != null) {
            returnval = new HardTokenView(availablehardtokens, token);
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public Collection getHardTokenIssuerDatas() throws RemoteException {
        return hardtokensession.getHardTokenIssuerDatas(admin);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public TreeMap getHardTokenIssuers() throws RemoteException {
        return hardtokensession.getHardTokenIssuers(admin);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String[] getHardTokenIssuerAliases() throws RemoteException {
        return (String[]) hardtokensession.getHardTokenIssuers(admin).keySet().toArray(new String[0]);
    }

    /**
     * Returns the alias from id.
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHardTokenIssuerAlias(int id) throws RemoteException {
        return hardtokensession.getHardTokenIssuerAlias(admin, id);
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getHardTokenIssuerId(String alias) throws RemoteException {
        return hardtokensession.getHardTokenIssuerId(admin, alias);
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public HardTokenIssuerData getHardTokenIssuerData(String alias)
        throws RemoteException {
        return hardtokensession.getHardTokenIssuerData(admin, alias);
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public HardTokenIssuerData getHardTokenIssuerData(int id)
        throws RemoteException {
        return hardtokensession.getHardTokenIssuerData(admin, id);
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     *
     * @throws HardTokenIssuerExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void addHardTokenIssuer(String alias, String certificatesn, String certissuerdn)
        throws HardTokenIssuerExistsException, RemoteException {
        certificatesn = StringTools.stripWhitespace(certificatesn);

        if (!hardtokensession.addHardTokenIssuer(admin, alias, new BigInteger(certificatesn, 16),
                    certissuerdn, new HardTokenIssuer())) {
            throw new HardTokenIssuerExistsException();
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     * @param hardtokenissuer DOCUMENT ME!
     *
     * @throws HardTokenIssuerExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void addHardTokenIssuer(String alias, String certificatesn, String certissuerdn,
        HardTokenIssuer hardtokenissuer) throws HardTokenIssuerExistsException, RemoteException {
        certificatesn = StringTools.stripWhitespace(certificatesn);

        if (!hardtokensession.addHardTokenIssuer(admin, alias, new BigInteger(certificatesn, 16),
                    certissuerdn, hardtokenissuer)) {
            throw new HardTokenIssuerExistsException();
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     * @param hardtokenissuer DOCUMENT ME!
     *
     * @throws HardTokenIssuerDoesntExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void changeHardTokenIssuer(String alias, HardTokenIssuer hardtokenissuer)
        throws HardTokenIssuerDoesntExistsException, RemoteException {
        if (!hardtokensession.changeHardTokenIssuer(admin, alias, hardtokenissuer)) {
            throw new HardTokenIssuerDoesntExistsException();
        }
    }

    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeHardTokenIssuer(String alias)
        throws RemoteException {
        boolean issuerused = false;
        int issuerid = hardtokensession.getHardTokenIssuerId(admin, alias);

        // Check if any users or authorization rule use the profile.
        issuerused = hardtokenbatchsession.checkForHardTokenIssuerId(admin, issuerid);

        if (!issuerused) {
            hardtokensession.removeHardTokenIssuer(admin, alias);
        }

        return !issuerused;
    }

    /**
     * DOCUMENT ME!
     *
     * @param oldalias DOCUMENT ME!
     * @param newalias DOCUMENT ME!
     * @param newcertificatesn DOCUMENT ME!
     * @param certissuersn DOCUMENT ME!
     *
     * @throws HardTokenIssuerExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void renameHardTokenIssuer(String oldalias, String newalias, String newcertificatesn,
        String certissuersn) throws HardTokenIssuerExistsException, RemoteException {
        newcertificatesn = StringTools.stripWhitespace(newcertificatesn);

        if (!hardtokensession.renameHardTokenIssuer(admin, oldalias, newalias,
                    new BigInteger(newcertificatesn, 16), certissuersn)) {
            throw new HardTokenIssuerExistsException();
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param oldalias DOCUMENT ME!
     * @param newalias DOCUMENT ME!
     * @param newcertificatesn DOCUMENT ME!
     * @param newcertissuerdn DOCUMENT ME!
     *
     * @throws HardTokenIssuerExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void cloneHardTokenIssuer(String oldalias, String newalias, String newcertificatesn,
        String newcertissuerdn) throws HardTokenIssuerExistsException, RemoteException {
        newcertificatesn = StringTools.stripWhitespace(newcertificatesn);

        if (!hardtokensession.cloneHardTokenIssuer(admin, oldalias, newalias,
                    new BigInteger(newcertificatesn, 16), newcertissuerdn)) {
            throw new HardTokenIssuerExistsException();
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AvailableHardToken[] getAvailableHardTokens() {
        return availablehardtokens;
    }

    // Private fields.
    private IHardTokenSessionRemote hardtokensession;
    private IHardTokenBatchJobSessionRemote hardtokenbatchsession;
    private AvailableHardToken[] availablehardtokens;
    private AdminInformation admininformation;
    private Admin admin;
    private boolean initialized = false;
    private HardTokenView[] result;
}
