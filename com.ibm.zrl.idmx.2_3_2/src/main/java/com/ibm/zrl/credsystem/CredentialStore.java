/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zrl.credsystem;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zrl.credsystem.Translator.HighLevelDataType;
import com.ibm.zrl.credsystem.utils.Parser;
import com.ibm.zrl.credsystem.utils.Utils;
import com.ibm.zrl.credsystem.utils.XMLSerializer;
import com.ibm.zrl.idmx.dm.Attribute;
import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.dm.MasterSecret;
import com.ibm.zrl.idmx.utils.Constants;

/**
 * Utility class that contains credentials that the user owns. All access to
 * credentials must be handled through this class.
 */
public class CredentialStore {

    /** Logger. */
    private static Logger log = Logger.getLogger(CredentialStore.class
            .getName());

    /** Map of all currently active credential stores. */
    private static HashMap<URI, CredentialStore> credStoreMap = new HashMap<URI, CredentialStore>();

    /** Location of the credentials. */
    private URI credentialStoreLocation;
    /** Location of the master secret. */
    private URI masterSecretLocation;
    private MasterSecret masterSecret;
    /** Location of the group parameters. */
    private URI groupParamsLocation;
    /** Translator for this credential store. */
    private Translator translator;
    /** Credentials that are currently loaded. */
    private final HashMap<String, Credential> credentialMap = new HashMap<String, Credential>();
    /**
     * Mapping of a a human recognisable object (e.g., an image or a name) to a
     * credential name.
     */
    private HashMap<Object, String> credentialNamesMap = new HashMap<Object, String>();

    /**
     * Loads all credentials in the indicated location.
     * 
     * @param storeLocation
     *            Location where credentials reside.
     * @param msLocation
     *            Location of the master secret, which may be different from the
     *            location of the credential store itself.
     */
    public static CredentialStore get(final URI storeLocation,
            final URI msLocation, final URI groupParametersLocation) {
        CredentialStore credStore = credStoreMap.get(storeLocation);
        if (credStore == null) {
            credStore = new CredentialStore();
            credStore.credentialStoreLocation = storeLocation;
            credStore.masterSecretLocation = msLocation;
            credStore.groupParamsLocation = groupParametersLocation;
            try {
                credStore.load();
            } catch (FileNotFoundException e) {
                log.log(Level.SEVERE, "Credential store cannot be created in "
                        + "the given location.");
            }
            credStore.update();
            credStoreMap.put(storeLocation, credStore);
            return credStore;
        }
        credStore.update();
        return credStore;
    }

    /**
     * Loads the basic files for the credential store (e.g., the translator).
     * 
     * @throws FileNotFoundException
     */
    @SuppressWarnings("unchecked")
    private final void load() throws FileNotFoundException {
        if (credentialStoreLocation.getScheme().equalsIgnoreCase("file")) {
            String[] files = getFiles("translator");
            if (files.length == 1) {
                translator = (Translator) Parser.getInstance().parse(
                        credentialStoreLocation.resolve(files[0]));
            } else {
                translator = new Translator();
            }
        } else {
            throw new RuntimeException("Scheme of credential store is not "
                    + "supported.");
        }

        if (credentialStoreLocation.getScheme().equalsIgnoreCase("file")) {
            String[] files = getFiles("credentialNames");
            if (files.length == 1) {
                credentialNamesMap = (HashMap<Object, String>) Parser
                        .getInstance().parse(
                                credentialStoreLocation.resolve(files[0]));
            } else {
                credentialNamesMap = new HashMap<Object, String>();
            }
        } else {
            throw new RuntimeException("Scheme of credential store is not "
                    + "supported.");
        }

        if (masterSecretLocation.getScheme().equalsIgnoreCase("file")) {
            masterSecret = (MasterSecret) Parser.getInstance().parse(
                    masterSecretLocation);
            if (masterSecret == null) {
                masterSecret = new MasterSecret(groupParamsLocation);
            }
        } else {
            throw new RuntimeException("Scheme of master secret location is "
                    + "not supported.");
        }
    }

    /**
     * @param nameFilter
     *            Defines a filter on the beginning of a file name.
     * @return List of files in the credential directory that end with
     *         <tt>.xml</tt>.
     */
    private final String[] getFiles(final String nameFilter) {
        File dir = new File(credentialStoreLocation);
        FilenameFilter filter = new FilenameFilter() {
            public boolean accept(File dir, String name) {
                if (name.endsWith(".xml") && name.startsWith(nameFilter)) {
                    return true;
                }
                return false;
            }
        };
        return dir.list(filter);
    }

    /**
     * Scans the credential location for new credentials and loads them.
     */
    public final void update() {

        System.out.println("Updating credential store...");

        if (credentialStoreLocation.getScheme().equalsIgnoreCase("file")) {
            // String[] files = getFiles("Credential_");
            // for (int i = 0; i < files.length; i++) {
            Iterator<Object> it = credentialNamesMap.keySet().iterator();
            while (it.hasNext()) {
                // String name = files[i];
                Object credentialIdentifier = it.next();
                String name = credentialNamesMap.get(credentialIdentifier);
                if (!credentialMap.containsKey(name)) {
                    Credential cred = (Credential) Parser.getInstance().parse(
                            credentialStoreLocation.resolve(name));
                    credentialMap.put(name, cred);
                }
            }
        } else {
            throw new RuntimeException("Scheme of credential store is not "
                    + "supported.");
        }
    }

    /**
     * Delegation method. This method delegates the request to the right
     * translator.
     * 
     * @param date
     *            Date to be encoded.
     * @param dataType
     *            Method of encoding.
     * @return BigInteger encoding the given date w.r.t. the given encoding.
     */
    public BigInteger encode(String date, HighLevelDataType dataType) {
        return translator.encode(date, dataType);
    }

    /**
     * Delegation method. This method delegates the request to the right
     * translator.
     * 
     * @param l_H
     *            Length of the hash function output.
     * @param value
     *            String to be encoded.
     * @return Encoding of the string by creating a hash.
     */
    public BigInteger encode(int l_H, String value) {
        return translator.encode(l_H, value);
    }

    /**
     * Gracefully closes a credential store (e.g., by writing the translation
     * map to a file).
     */
    public final void close() {
        XMLSerializer.getInstance().serialize(translator,
                credentialStoreLocation.resolve("translator.xml"));
        XMLSerializer.getInstance().serialize(masterSecret,
                masterSecretLocation);
        XMLSerializer.getInstance().serialize(credentialNamesMap,
                credentialStoreLocation.resolve("credentialNames.xml"));
    }

    /**
     * @param credName
     *            File name of a credential in the credential directory.
     * @return Credential from the given file name.
     */
    public Credential getCredential(String credName) {
        return credentialMap.get(credName);
    }

    /**
     * @param credName
     *            File name of the credential to be translated.
     * @return Credential with high level data as attribute values instead of
     *         their encodings.
     */
    public Credential getTranslatedCredential(String credName) {
        Credential cred = credentialMap.get(credName);
        Iterator<Attribute> iterator = cred.getAttributes().iterator();
        while (iterator.hasNext()) {
            Attribute att = iterator.next();
            String highLevelValue = translator.decode(att.getValue());
            att.setValueObject(highLevelValue);
        }
        return cred;
    }

    /**
     * @return Master secret
     */
    public final MasterSecret getMasterSecret() {
        return masterSecret;
    }

    public String put(Credential credential, Object information) {
        String name = "Credential_" + Utils.getRandomString(12) + ".xml";
        XMLSerializer.getInstance().serialize(credential,
                credentialStoreLocation.resolve(name));
        credentialMap.put(name, credential);
        // add it to the list of credentials
        credentialNamesMap.put(information, name);
        return name;
    }

    /**
     * @param name
     *            Human readable name, the credential has been assigned.
     * @param credIdentifier
     *            Proof specific identifier (used to make several credentials of
     *            the same type distinct within the scope of a proof).
     * @return Map containing the credential with name <code>name</code>.
     */
    public HashMap<String, Credential> download(String name,
            String credIdentifier) {
        HashMap<String, Credential> creds = new HashMap<String, Credential>();

        if (!credentialNamesMap.keySet().contains(name)) {
            return creds;
        }
        final Credential c = (Credential) Parser.getInstance().parse(
                credentialStoreLocation.resolve(credentialNamesMap.get(name)));
        String credTempName = c.getCredStructLocation().toString()
                .concat(Constants.DELIMITER).concat(credIdentifier);
        creds.put(credTempName, c);

        return creds;
    }
}
