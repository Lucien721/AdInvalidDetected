/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zrl.idmx.tests.idmx;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zrl.idmx.dm.MasterSecret;
import com.ibm.zrl.idmx.issuance.update.UpdateSpecification;
import com.ibm.zrl.idmx.key.IssuerKeyPair;
import com.ibm.zrl.idmx.key.IssuerPublicKey;
import com.ibm.zrl.idmx.key.VEPrivateKey;
import com.ibm.zrl.idmx.key.VEPublicKey;
import com.ibm.zrl.idmx.utils.GroupParameters;
import com.ibm.zrl.idmx.utils.Parser;
import com.ibm.zrl.idmx.utils.StructureStore;
import com.ibm.zrl.idmx.utils.SystemParameters;
import com.ibm.zrl.idmx.utils.XMLSerializer;

/**
 *
 */
public class Locations {

    /** Logger. */
    private static Logger log = Logger.getLogger(Locations.class.getName());

    /** Base URI of the actual location of all the files. */
    private static URI BASE_LOCATION = null;
    /** Location of issuer related files (e.g., ipk, credStructs). */
    private static URI ISSUER_LOCATION = null;
    /** Location of files related to a trusted party (e.g., vepk). */
    private static URI TRUSTED_PARTY_LOCATION = null;
    /** Location where updates for credentials can be fetched. */
    private static URI UPDATE_LOCATION = null;

    /** Location of proof specifications used in the tests. */
    private static URI PROOF_SPECIFICATION_LOCATION = null;
    /** Location of credentials. */
    private static URI CREDENTIAL_LOCATION = null;
    /** Location of private files (e.g., isk, ms) */
    private static URI PRIVATE_LOCATION = null;
    /** Location where all the elements that would be sent are stored. */
    private static URI SEND_LOCATION = null;

    /** ID which identify an element (this does NOT point to an actual file). */
    private static URI BASE_ID = null;
    /** ID for issuer related elements. */
    private static URI ISSUER_ID = null;
    /** ID for trusted party related elements. */
    private static URI TRUSTED_PARTY_ID = null;

    public static URI gpUri;
    public static URI spUri;
    public static URI iskUri;
    public static URI ipkUri;
    public static URI msUri;
    public static URI vepkUri;
    public static URI veskUri;

    public static URI gpIdUri;
    public static URI ipkIdUri;
    public static URI vepkIdUri;

    /**
     * Initialise all paths needed for a complete test of the Identity Mixer
     * library. Note that these paths must point to actual locations (online or
     * locally) where the corresponding files are located.
     * 
     * @param baseLocation
     *            Locaiton of all files for a test of the library.
     */
    protected static void initLocationsComplete(String baseLocation) {
        try {
            BASE_LOCATION = new URI(baseLocation);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        ISSUER_LOCATION = BASE_LOCATION.resolve("../testIssuer/");
        TRUSTED_PARTY_LOCATION = BASE_LOCATION.resolve("../testTrustedParty/");
        UPDATE_LOCATION = BASE_LOCATION.resolve("../update/");
        // The following locations are not known to the communication
        // partner (thus there are no corresponding IDs).
        PROOF_SPECIFICATION_LOCATION = BASE_LOCATION
                .resolve("../proofSpecifications/");
        CREDENTIAL_LOCATION = BASE_LOCATION.resolve("../credentials/");
        PRIVATE_LOCATION = BASE_LOCATION.resolve("../private/");
        SEND_LOCATION = BASE_LOCATION.resolve("../send/");

        gpUri = getParameterLocation("gp");
        spUri = getParameterLocation("sp");
        iskUri = getPrivateLocation("isk");
        ipkUri = getIssuerLocation("ipk");
        msUri = getPrivateLocation("ms");
        vepkUri = getTrustedPartyLocation("vepk");
        veskUri = getPrivateLocation("vesk");
    }

    /**
     * Initialise the URIs that are used within the XML files. We use those URIs
     * as we don't want to use locations on the local file system within the
     * files.
     * 
     * @param baseId
     *            Base URI (e.g.,
     *            <code>http://www.zurich.ibm.com/security/idmx/v2</code>)
     * @return System parameters loaded from a local file (according to the
     *         location information).
     */
    protected static SystemParameters initIdsComplete(String baseId) {
        // IDs for the public parameters
        SystemParameters sp = initBaseId(baseId);
        initIssuerId(BASE_ID.resolve("testIssuer/").toString());
        initTrustedPartyId(BASE_ID.resolve("testTrustedParty/").toString());
        return sp;
    }

    protected static final SystemParameters initBaseId(String baseId) {
        try {
            BASE_ID = new URI(baseId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        gpIdUri = getParameterId("gp");

        SystemParameters sp = (SystemParameters) StructureStore.getInstance()
                .get(getParameterId("sp").toString(), spUri);
        GroupParameters gp = (GroupParameters) StructureStore.getInstance()
                .get(gpIdUri.toString(), gpUri);
        if (gp == null) {
            gp = GroupParameters.generateGroupParams(spUri);
            try {
                XMLSerializer.getInstance().serialize(gp, gpUri);
                StructureStore.getInstance().get(gpIdUri.toString(), gpUri);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (gp.getSystemParams() == null) {
            throw new RuntimeException("System parameters are not correctly "
                    + "referenced in group parameters: " + gpUri.toString());
        }
        return sp;
    }

    public static final IssuerPublicKey initIssuerId(String issuerId) {
        try {
            ISSUER_ID = new URI(issuerId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        ipkIdUri = getIssuerId("ipk");
        return getIssuerPublicKey();
    }

    protected static final VEPublicKey initTrustedPartyId(String trustedPartyId) {
        try {
            TRUSTED_PARTY_ID = new URI(trustedPartyId);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        vepkIdUri = getTrustedPartyId("vepk");
        return getVEPublicKey();
    }

    public static SystemParameters loadParameters(String baseId,
            String baseLocation) {
        // init URIs with the correct values
        initLocationsComplete(baseLocation);

        // loading of structures from files (as they are not located in the
        // location indicated in the file).
        return initIdsComplete(baseId);
    }

    protected static final UpdateSpecification loadUpdateSpecification(
            String name) {
        name = "updateSpecification_" + name;
        URI updateSpecUri = getIssuerLocation(name);
        return (UpdateSpecification) StructureStore.getInstance().get(
                getIssuerId(name).toString(), updateSpecUri);
    }

    public static final void loadCredStruct(String name) {
        URI credStructUri = getIssuerLocation(name);
        StructureStore.getInstance().get(getIssuerId(name).toString(),
                credStructUri);
    }

    public static final URI getUpdateLocation() {
        if (UPDATE_LOCATION != null) {
            return UPDATE_LOCATION;
        } else {
            throw new RuntimeException("Update location not initialised!");
        }
    }

    public static final URI getCredentialLocation() {
        if (CREDENTIAL_LOCATION != null) {
            return CREDENTIAL_LOCATION;
        } else {
            throw new RuntimeException("Credential location not initialised!");
        }
    }

    protected static final String getFileExtension(String fileBaseName) {
        return fileBaseName + ".xml";
    }

    protected static final URI getParameterLocation(String fileBaseName) {
        return BASE_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    protected static final URI getParameterId(String fileBaseName) {
        return BASE_ID.resolve(getFileExtension(fileBaseName));
    }

    protected static final URI getIssuerLocation(String fileBaseName) {
        return ISSUER_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    public static final URI getIssuerId(String fileBaseName) {
        return ISSUER_ID.resolve(getFileExtension(fileBaseName));
    }

    protected static final URI getTrustedPartyLocation(String fileBaseName) {
        return TRUSTED_PARTY_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    protected static final URI getTrustedPartyId(String fileBaseName) {
        return TRUSTED_PARTY_ID.resolve(getFileExtension(fileBaseName));
    }

    public static final URI getProofSpecLocation(String fileBaseName) {
        return PROOF_SPECIFICATION_LOCATION.resolve(fileBaseName + ".xml");
    }

    public static final URI getCredentialLocation(String fileBaseName) {
        return CREDENTIAL_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    public static final URI getPrivateLocation(String fileBaseName) {
        return PRIVATE_LOCATION.resolve(getFileExtension(fileBaseName));
    }

    public static URI getSendLocation(String fileBaseName) {
        return SEND_LOCATION.resolve(fileBaseName + ".xml");
    }

    protected static URI getProofLocation(String fileBaseName) {
        return getSendLocation(fileBaseName + "_proof");
    }

    protected static URI getNonceLocation(String fileBaseName) {
        return getSendLocation(fileBaseName + "_nonce");
    }

    protected static MasterSecret getMasterSecret() {
        MasterSecret masterSecret = (MasterSecret) Parser.getInstance().parse(
                msUri);
        if (masterSecret == null) {
            masterSecret = new MasterSecret(Locations.gpIdUri);
            XMLSerializer.getInstance()
                    .serialize(masterSecret, Locations.msUri);
        }
        return masterSecret;
    }

    protected static IssuerPublicKey getIssuerPublicKey() {
        return (IssuerPublicKey) StructureStore.getInstance().get(
                ipkIdUri.toString(), ipkUri);

    }

    public static IssuerKeyPair getIssuerKey() {
        IssuerKeyPair issuerKey = null;
        try {
            issuerKey = (IssuerKeyPair) StructureStore.getInstance().get(
                    Locations.iskUri);
        } catch (Exception e) {
            log.log(Level.INFO, "Issuer secred key not found in "
                    + Locations.iskUri.toString() + ". I will generate "
                    + "a new one. If you are running the test case for "
                    + "the first time this is nothing to worry about!");
        }
        if ((issuerKey == null) || (issuerKey.getPublicKey() == null)) {
            issuerKey = new IssuerKeyPair(Locations.ipkIdUri,
                    Locations.gpIdUri, KeyPair.NBR_ATTRS, KeyPair.EPOCH_LENGTH);
            XMLSerializer.getInstance().serialize(issuerKey.getPublicKey(),
                    Locations.ipkUri);
            XMLSerializer.getInstance().serialize(issuerKey.getPrivateKey(),
                    Locations.iskUri);

            // remove previous entries in the structure store database and load
            // them through the structure store to make the right keys
            // accessible
            StructureStore.getInstance().remove(Locations.iskUri);
            StructureStore.getInstance().remove(Locations.ipkIdUri);

            getIssuerPublicKey();
            issuerKey = (IssuerKeyPair) StructureStore.getInstance().get(
                    Locations.iskUri);
        }

        return issuerKey;
    }

    protected static final VEPublicKey getVEPublicKey() {
        // try to load VE keypair
        VEPublicKey pk = (VEPublicKey) StructureStore.getInstance().get(
                vepkIdUri.toString(), vepkUri);
        if (pk == null) {
            getVEPrivateKey();
            pk = (VEPublicKey) StructureStore.getInstance().get(
                    vepkIdUri.toString(), vepkUri);
        }
        return pk;
    }

    protected static final VEPrivateKey getVEPrivateKey() {
        // try to load VE keypair
        VEPublicKey pk = (VEPublicKey) StructureStore.getInstance().get(
                vepkIdUri.toString(), vepkUri);
        VEPrivateKey sk = (VEPrivateKey) StructureStore.getInstance().get(
                veskUri);
        if (pk == null || sk == null) {
            log.log(Level.INFO, "Verifiable encryption key failed to load. "
                    + "Generating a new one and saving it...");
            sk = new VEPrivateKey(Locations.spUri, vepkUri);
            pk = sk.getPublicKey();

            XMLSerializer.getInstance().serialize(pk, vepkUri);
            XMLSerializer.getInstance().serialize(sk, veskUri);
        }
        return sk;
    }

}
