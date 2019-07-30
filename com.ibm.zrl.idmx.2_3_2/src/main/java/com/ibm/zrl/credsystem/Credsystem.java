/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zrl.credsystem;

import java.io.StringReader;
import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;

import org.xml.sax.InputSource;

import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.showproof.Proof;
import com.ibm.zrl.idmx.showproof.ProofSpec;
import com.ibm.zrl.idmx.showproof.Prover;
import com.ibm.zrl.idmx.utils.Constants;
import com.ibm.zrl.idmx.utils.Parser;
import com.ibm.zrl.idmx.utils.XMLSerializer;

/**
 *
 */
public class Credsystem {

    /** Credential store. */
    private CredentialStore credentialStore;

    public Credsystem(URI location) {

    }

    /**
     * @param credName
     *            File name of the credential.
     * @param tempCredName
     *            Temporary name of the credential in the proof specification.
     * @return
     */
    private HashMap<String, Credential> loadCredential(String credName,
            String tempCredName) {
        // update credential store (not strictly necessary if no new credentials
        // have been added)
        credentialStore.update();
        final Credential c = credentialStore.getCredential(credName);

        HashMap<String, Credential> creds = new HashMap<String, Credential>();
        String credTempName = c.getCredStructLocation().toString()
                .concat(Constants.DELIMITER).concat(tempCredName);
        creds.put(credTempName, c);
        return creds;
    }

    public String requestProof(String proofSpecification, String nonceString) {
        InputSource is = new InputSource();
        is.setCharacterStream(new StringReader(proofSpecification));
        ProofSpec spec = (ProofSpec) Parser.getInstance().parse(is);

        // first get the nonce (done by the verifier)
        BigInteger nonce = new BigInteger(nonceString);

        // TODO (pbi) require authentication towards credential!

        // add the credential to the currently used credentials
        HashMap<String, Credential> creds = loadCredential(
                "Credential_UtopiaHiddenValues.xml", "dsk239fsk23er90");

        Prover prover = new Prover(credentialStore.getMasterSecret(), creds,
                spec, nonce);

        // create the proof
        Proof p = prover.buildProof();

        String proofString = null;
        try {
            proofString = XMLSerializer.getInstance().serialize(p);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // save the proof
        return proofString;
    }
}
