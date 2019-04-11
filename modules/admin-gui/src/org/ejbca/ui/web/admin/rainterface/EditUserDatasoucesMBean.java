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
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * @version $Id$
 */
public class EditUserDatasoucesMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditUserDatasoucesMBean.class);

    private DatasourceGui datasourceGui = null;
    private UserDatasoucesMBean userDatasoucesMBean;
    private TreeMap<String, Integer> modifyableFieldTexts = null;

    @EJB
    private UserDataSourceSessionLocal userdatasourcesession;

    public class DatasourceGui {
        private String name;
        private int type;
        private String description;
        private Set<Integer> modifiableFields;
        private Collection<Integer> applicableCAs;
        private String classPath;
        private String propertyData;
        private boolean isCustomUserDatasource;

        public DatasourceGui(String name, int type, String description, Set<Integer> modifiableFields, Collection<Integer> applicableCAs) {
            this.name = name;
            this.type = type;
            this.description = description;
            this.modifiableFields = modifiableFields;
            this.applicableCAs = applicableCAs;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getType() {
            return type;
        }

        public void setType(int type) {
            this.type = type;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public Set<Integer> getModifiableFields() {
            return modifiableFields;
        }

        public void setModifiableFields(Set<Integer> modifiableFields) {
            this.modifiableFields = modifiableFields;
        }

        public Collection<Integer> getApplicableCAs() {
            return applicableCAs;
        }

        public void setApplicableCAs(Collection<Integer> applicableCAs) {
            this.applicableCAs = applicableCAs;
        }

        public String getClassPath() {
            return classPath;
        }

        public void setClassPath(String classPath) {
            this.classPath = classPath;
        }

        public String getPropertyData() {
            return propertyData;
        }

        public void setPropertyData(String propertyData) {
            this.propertyData = propertyData;
        }

        public boolean isCustomUserDatasource() {
            return isCustomUserDatasource;
        }

        public void setCustomUserDatasource(boolean customUserDatasource) {
            isCustomUserDatasource = customUserDatasource;
        }
    }

    public DatasourceGui getDatasource() {
        if (datasourceGui == null) {
            BaseUserDataSource userDataSource = userdatasourcesession.getUserDataSource(getAdmin(), userDatasoucesMBean.getSelectedUserDataSource());
            datasourceGui = new DatasourceGui(userDatasoucesMBean.getSelectedUserDataSource(), getUserDataSourceType(userDataSource),
                    userDataSource.getDescription(),
                    userDataSource.getModifiableFields(),
                    userDataSource.getApplicableCAs());
            if (userDataSource instanceof CustomUserDataSourceContainer) {
                datasourceGui.setCustomUserDatasource(true);
                datasourceGui.setClassPath(((CustomUserDataSourceContainer) userDataSource).getClassPath());
                datasourceGui.setPropertyData(((CustomUserDataSourceContainer) userDataSource).getPropertyData());
            }
        }
        return datasourceGui;
    }


    public List<SelectItem> getUserDatasourceTypeItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER, EjbcaJSFHelper.getBean().getText().get("CUSTOMUSERDATASOURCE")));
        return ret;
    }

    public List<SelectItem> getModifyableFieldSeletItemList() {
        TreeMap<String, Integer> modifyableFieldTexts = getModifyableFieldTexts();
        final List<SelectItem> ret = new ArrayList<>();
        for (Map.Entry<String, Integer> modifyableField : modifyableFieldTexts.entrySet()) {
            ret.add(new SelectItem(modifyableField.getValue(), modifyableField.getKey()));
        }
        return ret;
    }

    public List<SelectItem> getApplicableCAsSeletItemList() {
        TreeMap<String, Integer> caNames = getEjbcaWebBean().getCANames();
        final List<SelectItem> ret = new ArrayList<>();
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.ROLE_ROOT.resource())) {
            ret.add(new SelectItem(BaseUserDataSource.ANYCA, EjbcaJSFHelper.getBean().getText().get("ANYCA")));
        }
        for (Map.Entry<String, Integer> modifyableField : caNames.entrySet()) {
            ret.add(new SelectItem(modifyableField.getValue(), modifyableField.getKey()));
        }
        return ret;
    }


    public UserDatasoucesMBean getUserDatasoucesMBean() {
        return userDatasoucesMBean;
    }

    public void setUserDatasoucesMBean(UserDatasoucesMBean userDatasoucesMBean) {
        this.userDatasoucesMBean = userDatasoucesMBean;
    }

    private int getUserDataSourceType(BaseUserDataSource userdatasourcedata) {
        int retval = CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER;

        if (userdatasourcedata instanceof CustomUserDataSourceContainer) {
            retval = CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER;
        }

        return retval;
    }

    public String save() throws AuthorizationDeniedException {
        BaseUserDataSource userdatasourcedata = fillUserDatasourceData();
        userdatasourcesession.changeUserDataSource(getAdmin(), datasourceGui.name, userdatasourcedata);
        reset();
        return "done";
    }

    private BaseUserDataSource fillUserDatasourceData() {
        BaseUserDataSource userdatasourcedata = new CustomUserDataSourceContainer();
        userdatasourcedata.setDescription(datasourceGui.getDescription());
        userdatasourcedata.setModifiableFields(datasourceGui.getModifiableFields());
        userdatasourcedata.setApplicableCAs(datasourceGui.getApplicableCAs());
        ((CustomUserDataSourceContainer) userdatasourcedata).setClassPath(datasourceGui.getClassPath());
        ((CustomUserDataSourceContainer) userdatasourcedata).setPropertyData(datasourceGui.getPropertyData());
        return userdatasourcedata;
    }

    public String saveAndTest() throws AuthorizationDeniedException {
        BaseUserDataSource userdatasourcedata = fillUserDatasourceData();
        userdatasourcesession.changeUserDataSource(getAdmin(), datasourceGui.name, userdatasourcedata);
        try {
            int userdatasourceid = userdatasourcesession.getUserDataSourceId(getAdmin(), datasourceGui.name);
            userdatasourcesession.testConnection(getAdmin(), userdatasourceid);
            addInfoMessage("CONTESTEDSUCESSFULLY");
            reset();
            return "done";
        } catch (UserDataSourceConnectionException | RuntimeException pce) {
            String errorMessage = getEjbcaWebBean().getText("ERRORCONNECTINGTOPUB");
            log.info(errorMessage, pce);
            addNonTranslatedErrorMessage(errorMessage + " : " + pce.getMessage());
            return StringUtils.EMPTY;
        }
    }

    public String cancel() {
        reset();
        return "done";
    }

    private void reset() {
        datasourceGui = null;
        userDatasoucesMBean.actionCancel();
    }


    public TreeMap<String, Integer> getModifyableFieldTexts() {
        if (modifyableFieldTexts == null) {
            modifyableFieldTexts = new TreeMap<>();

            String subjectdntext = getEjbcaWebBean().getText("CERT_SUBJECTDN");
            String subjectaltnametext = getEjbcaWebBean().getText("EXT_ABBR_SUBJECTALTNAME");
            String subjectdirattrtext = getEjbcaWebBean().getText("EXT_ABBR_SUBJECTDIRATTRS");

            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_UID"), Integer.valueOf(DNFieldExtractor.UID));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_COMMONNAME"), Integer.valueOf(DNFieldExtractor.CN));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_SERIALNUMBER"), Integer.valueOf(DNFieldExtractor.SN));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_GIVENNAME"), Integer.valueOf(DNFieldExtractor.GIVENNAME));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_INITIALS"), Integer.valueOf(DNFieldExtractor.INITIALS));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_SURNAME"), Integer.valueOf(DNFieldExtractor.SURNAME));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_TITLE"), Integer.valueOf(DNFieldExtractor.T));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_ORGANIZATIONALUNIT"), Integer.valueOf(DNFieldExtractor.OU));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_ORGANIZATION"), Integer.valueOf(DNFieldExtractor.O));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_LOCALITY"), Integer.valueOf(DNFieldExtractor.L));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_STATEORPROVINCE"), Integer.valueOf(DNFieldExtractor.ST));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_DOMAINCOMPONENT"), Integer.valueOf(DNFieldExtractor.DC));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_COUNTRY"), Integer.valueOf(DNFieldExtractor.C));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_UNSTRUCTUREDADDRESS"), Integer.valueOf(DNFieldExtractor.UNSTRUCTUREDADDRESS));
            modifyableFieldTexts.put(subjectdntext + " : " + getEjbcaWebBean().getText("DN_PKIX_UNSTRUCTUREDNAME"), Integer.valueOf(DNFieldExtractor.UNSTRUCTUREDNAME));

            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_DNSNAME"), Integer.valueOf(DNFieldExtractor.DNSNAME));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_IPADDRESS"), Integer.valueOf(DNFieldExtractor.IPADDRESS));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_DIRECTORYNAME"), Integer.valueOf(DNFieldExtractor.DIRECTORYNAME));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_UNIFORMRESOURCEID"), Integer.valueOf(DNFieldExtractor.URI));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_MS_UPN"), Integer.valueOf(DNFieldExtractor.UPN));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_MS_GUID"), Integer.valueOf(DNFieldExtractor.GUID));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_KERBEROS_KPN"), Integer.valueOf(DNFieldExtractor.KRB5PRINCIPAL));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_PERMANENTIDENTIFIER"), Integer.valueOf(DNFieldExtractor.PERMANTIDENTIFIER));
            modifyableFieldTexts.put(subjectaltnametext + " : " + getEjbcaWebBean().getText("ALT_PKIX_SUBJECTIDENTIFICATIONMETHOD"), Integer.valueOf(DNFieldExtractor.SUBJECTIDENTIFICATIONMETHOD));

            modifyableFieldTexts.put(subjectdirattrtext + " : " + getEjbcaWebBean().getText("SDA_DATEOFBIRTH"), Integer.valueOf(DNFieldExtractor.DATEOFBIRTH));
            modifyableFieldTexts.put(subjectdirattrtext + " : " + getEjbcaWebBean().getText("SDA_PLACEOFBIRTH"), Integer.valueOf(DNFieldExtractor.PLACEOFBIRTH));
            modifyableFieldTexts.put(subjectdirattrtext + " : " + getEjbcaWebBean().getText("SDA_GENDER"), Integer.valueOf(DNFieldExtractor.GENDER));
            modifyableFieldTexts.put(subjectdirattrtext + " : " + getEjbcaWebBean().getText("SDA_COUNTRYOFCITIZENSHIP"), Integer.valueOf(DNFieldExtractor.COUNTRYOFCITIZENSHIP));
            modifyableFieldTexts.put(subjectdirattrtext + " : " + getEjbcaWebBean().getText("SDA_COUNTRYOFRESIDENCE"), Integer.valueOf(DNFieldExtractor.COUNTRYOFRESIDENCE));


            modifyableFieldTexts.put(getEjbcaWebBean().getText("USERNAME"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_USERNAME));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("PASSWORD"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_PASSWORD));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("CA"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_CAID));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("EMAIL"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_EMAILDATA));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("PASSWORD"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_TYPE));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("ENDENTITYPROFILE"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_ENDENTITYPROFILE));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("CERTIFICATEPROFILE"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_CERTIFICATEPROFILE));
            modifyableFieldTexts.put(getEjbcaWebBean().getText("TOKEN"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_TOKENTYPE));

        }
        return modifyableFieldTexts;
    }
}
