/**
 * Copyright IBM Corporation 2009
 */
package com.ibm.zrl.idmx.tests.credsystem;

import java.math.BigInteger;
import java.util.HashMap;

import junit.framework.TestCase;

import org.junit.After;
import org.junit.Before;

import com.ibm.zrl.credsystem.CredentialStore;
import com.ibm.zrl.credsystem.Translator.HighLevelDataType;
import com.ibm.zrl.credsystem.utils.Parser;
import com.ibm.zrl.credsystem.utils.XMLSerializer;
import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.dm.Values;
import com.ibm.zrl.idmx.issuance.IssuanceSpec;
import com.ibm.zrl.idmx.issuance.Issuer;
import com.ibm.zrl.idmx.issuance.Message;
import com.ibm.zrl.idmx.issuance.Recipient;
import com.ibm.zrl.idmx.key.IssuerKeyPair;
import com.ibm.zrl.idmx.showproof.Proof;
import com.ibm.zrl.idmx.showproof.ProofSpec;
import com.ibm.zrl.idmx.showproof.Prover;
import com.ibm.zrl.idmx.showproof.Verifier;
import com.ibm.zrl.idmx.tests.idmx.Locations;
import com.ibm.zrl.idmx.tests.idmx.TestIssuance;
import com.ibm.zrl.idmx.tests.idmx.TestProof;
import com.ibm.zrl.idmx.utils.StructureStore;
import com.ibm.zrl.idmx.utils.SystemParameters;

/**
 *
 */
public class TestCredsystem extends TestCase {

    /** Key pair of the issuer. */
    private IssuerKeyPair issuerKey = null;
    /** Key pair of the issuer. */
    private CredentialStore credStore = null;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        
        TestIssuance.initIdmx();
        
        Locations.loadParameters(TestIssuance.BASE_ID,
                TestIssuance.BASE_LOCATION);

        Locations
                .initIssuerId("http://www.zurich.ibm.com/security/idmx/v2/testIssuer/");

        issuerKey = Locations.getIssuerKey();

        // loading all credential structures to make sure they are available
        TestProof.preloadCredStructs();

        Locations.initIssuerId("http://www.ch.ch/identityCard/v2012/");
        Locations.loadCredStruct("CredStructComplete");

        Locations
                .initIssuerId("http://www.zurich.ibm.com/~pbi/idmx_2-3/utopia/");
        Locations.loadCredStruct("CredStruct_UtopiaHiddenValues");

        credStore = CredentialStore.get(Locations.getCredentialLocation(),
                Locations.getPrivateLocation("ms"), Locations.gpIdUri);
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
        credStore.close();
    }

    /**
     * Test: Issues a credential and saves it to an XML file.
     * 
     * This credential is used in the demonstrator of PrimeLife.
     * 
     * @see TestIssuance#CREDENTIAL_UTOPIAHIDDENVALUES
     */
    public final void testIssuance_Utopia_HiddenValues() {
        // create the issuance specification
        IssuanceSpec issuanceSpec = new IssuanceSpec(
                Locations.getIssuerId("CredStruct_"
                        + "UtopiaHiddenValues"));

        final String firstName = "Markus";
        final String lastName = "Meier";
        // Note, the date MUST be in the right format (which is defined by the
        // credential structure). It will be sanitized when parsed (e.g.,
        // setting the string to 2010/02/31 will automatically roll over to
        // march).
        final String dob = "1997/02/30";

        // Note, if you want to make a standalone application, load the
        // appropriate values as in setUp(). If the URIs indicated in the xml
        // files are working URLs, you will not have to bother with using 'Locations.initBaseLocations(String)' otherwise you can use this functionality to load files that are not in the location indicated in the files.

        Values values = new Values(issuerKey.getPublicKey().getGroupParams()
                .getSystemParams());
        int l_H = issuerKey.getPublicKey().getGroupParams().getSystemParams()
                .getL_H();

        values.add("firstName", credStore.encode(l_H, firstName));
        values.add("lastName", credStore.encode(l_H, lastName));
        values.add("dateOfBirth", credStore.encode(dob,
                HighLevelDataType.DATEFORMATDAY_GMT_PLUS_0));

        // run the issuance protocol.
        Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null, values);

        Recipient recipient = new Recipient(issuanceSpec,
                credStore.getMasterSecret(), values);

        Message msgToIssuer1 = recipient.round1(issuer.getNonce1());
        if (msgToIssuer1 == null) {
            fail("Failed in round 1...");
        }

        XMLSerializer.getInstance().serialize(msgToIssuer1,
                Locations.getSendLocation("utopia"));

        // ------------------ Transmission of message ------------------

        msgToIssuer1 = (Message) Parser.getInstance().parse(
                Locations.getSendLocation("utopia"));

        Message msgToRecipient2 = issuer.round2(msgToIssuer1);

        if (msgToRecipient2 == null) {
            fail("Failed in round 2...");
        }

        XMLSerializer.getInstance().serialize(msgToRecipient2,
                Locations.getSendLocation("utopia"));

        // ------------------ Transmission of message ------------------

        msgToRecipient2 = (Message) Parser.getInstance().parse(
                Locations.getSendLocation("utopia"));

        Credential cred = recipient.round3(msgToRecipient2);

        if (cred == null) {
            fail("Failed in round 3...");
        }

        // the credential name should be remembered and associated with some
        // user recognisable information (e.g., an image)
        // Note that we overwrite the previous entry with the new one by having
        // a constant string as information.
        credStore.put(cred, "Utopia credential");
    }

    /**
     * Test: Creates a proof according to a proof specification.
     * 
     * This credential is used in the demonstrator of PrimeLife.
     * 
     */
    public final void testProve_UtopiaHiddenValues() {

        // load the proof specification
        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
                Locations.getProofSpecLocation("ProofSpec_UtopiaHiddenValues"));
        System.out.println(spec.toStringPretty());

        SystemParameters sp = spec.getGroupParams().getSystemParams();

        // first get the nonce (done by the verifier)
        System.out.println("Getting nonce.");
        BigInteger nonce = Verifier.getNonce(sp);

        // add the credential to the currently used credentials
        HashMap<String, Credential> creds = credStore.download(
                "Utopia credential", "dsk239fsk23er90");

        Prover prover = new Prover(credStore.getMasterSecret(), creds, spec,
                nonce);
        // create the proof
        Proof p = prover.buildProof();
        System.out.println("Proof Created.");

        String proofString = null;
        try {
            proofString = XMLSerializer.getInstance().serialize(p);
            System.out.println(proofString);
        } catch (Exception e) {
            e.getStackTrace();
        }

        String nonceString = XMLSerializer.getInstance().serialize(nonce);

        // ------------------ Transmission of message ------------------

        BigInteger nonceVerifier = (BigInteger) Parser.getInstance().parse(
                nonceString);

        Proof pVerifier = (Proof) Parser.getInstance().parse(proofString);

        // now p is sent to the verifier
        Verifier verifier = new Verifier(spec, pVerifier, nonceVerifier);
        if (!verifier.verify()) {
            fail("The proof does not verify");
        } else {
            System.out.println(TestProof.PROOF_VERIFIED);
        }
    }

}
