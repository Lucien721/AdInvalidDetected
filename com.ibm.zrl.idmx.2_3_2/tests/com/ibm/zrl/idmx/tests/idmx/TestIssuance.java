/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.tests.idmx;

import java.math.BigInteger;
import java.util.HashSet;

import junit.framework.TestCase;

import com.ibm.zrl.idmx.dm.Commitment;
import com.ibm.zrl.idmx.dm.CommitmentOpening;
import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.dm.DomNym;
import com.ibm.zrl.idmx.dm.MasterSecret;
import com.ibm.zrl.idmx.dm.Values;
import com.ibm.zrl.idmx.issuance.Message;
import com.ibm.zrl.idmx.issuance.IssuanceSpec;
import com.ibm.zrl.idmx.issuance.Issuer;
import com.ibm.zrl.idmx.issuance.Recipient;
import com.ibm.zrl.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zrl.idmx.key.IssuerKeyPair;
import com.ibm.zrl.idmx.key.IssuerPublicKey;
import com.ibm.zrl.idmx.utils.Constants;
import com.ibm.zrl.idmx.utils.SystemParameters;
import com.ibm.zrl.idmx.utils.Utils;
import com.ibm.zrl.idmx.utils.XMLSerializer;

/**
 * Test cases to cover issuance of credentials.
 */
public class TestIssuance extends TestCase {

    /** Id that is used within the test files to identify the elements. */
    public static final String BASE_ID = "http://www.zurich.ibm.com/security"
            + "/idmx/v2/";
    /** Actual location of the files. */
    public static final String BASE_LOCATION = "file:///G:/eclipse-workspace/com.ibm.zrl.idmx.2_3_2/tests/com/ibm/zrl/idmx/tests/files/parameter/";

    public String sercet_Number = "13256785678";
    /** Attribute value 1313. */
    public BigInteger ATTRIBUTE_VALUE_1 = new BigInteger(sercet_Number);
    /** Attribute value 1314. */
    public static final BigInteger ATTRIBUTE_VALUE_2 = BigInteger.valueOf(0);
    /** Attribute value 1315. */
    public static final BigInteger ATTRIBUTE_VALUE_3 = BigInteger.valueOf(0);
    /** Attribute value 1316. */
    public static final BigInteger ATTRIBUTE_VALUE_4 = BigInteger.valueOf(0);
    /**
     * File name of the credential.
     */
    public static final String CREDENTIAL_UTOPIAHIDDENVALUES = "Credential_UtopiaHiddenValues.xml";
    /**
     * Credential structure.
     * <ol>
     * <li>arrt1: known: int</li>
     * <li>arrt2: known: int</li>
     * <li>arrt3: known: int</li>
     * <li>arrt4: known: int</li>
     * </ol>
     */

    public static final String CRED_STRUCT_1A = "CredStruct1a";
    /**
     * Credential structure.
     * <ol>
     * <li>arrt1: hidden: int</li>
     * <li>arrt2: hidden: int</li>
     * <li>arrt3: hidden: int</li>
     * <li>arrt4: hidden: int</li>
     * </ol>
     */
    public static final String CRED_STRUCT_COMPLETE = "CredStructComplete";

    /**
     * Credential.<br/>
     * <ol>
     * <li>attr1:1313/ATTRIBUTE_VALUE_1</li>
     * <li>attr2:1314/ATTRIBUTE_VALUE_2</li>
     * <li>attr3:1315/ATTRIBUTE_VALUE_3</li>
     * <li>attr4:1316/ATTRIBUTE_VALUE_4</li>
     * </ol>
     * 
     * @see TestIssuance#CRED_STRUCT_1A
     */
    public static final String CRED1A_FN = "Credential_1a";
    /**
     * Credential.<br/>
     * attr1:1313/ATTRIBUTE_VALUE_1 (hidden) <br/>
     * attr2:1314/ATTRIBUTE_VALUE_2 (hidden) <br/>
     * attr3:1315/ATTRIBUTE_VALUE_3 (hidden) <br/>
     * attr4:1316/ATTRIBUTE_VALUE_4 (hidden) <br/>
     * 
     * @see TestIssuance#CRED_STRUCT_1B
     */

    public static final String CRED_COMPLETE_FN = "Credential_complete";

    /** Key pair of the issuer. */
    private IssuerKeyPair issuerKey = null;
    /** Master secret to be used for this tests. */
    private MasterSecret masterSecret = null;
    /** System Parameters. */
    private SystemParameters sp;

    /**
     * Error message when running the library for the first time and not having
     */
    public static final void initIdmx() {
        if (BASE_LOCATION == null) {
            System.out.println("There is not BASE_Location specified! "
                    + "Please read the Application Developer Tutorial "
                    + "provided in the doc/getting_started/index.html.");
            fail("BASE_LOCATION is not configured");
        }
    }

    /**
     * Setup of the test environment.
     */
    protected final void setUp() {

    	initIdmx();
        sp = Locations.loadParameters(BASE_ID, BASE_LOCATION);
        issuerKey = Locations.getIssuerKey();
        masterSecret = Locations.getMasterSecret();
        
    }

    /**
     * Executed upon finishing the test run.
     */
    protected final void tearDown() {

    }

    /**
     * Test: Reads the library version and fails if the version is not the
     * expected version.
     */
    public final void testVersion() {
        if (Constants.getVersion() != "2.3.2") {
            fail("wrong version");
        }
    }
    /**
     * Test: Issues a credential.
     * 
     * @see TestIssuance#CRED_STRUCT_1A
     * @see TestIssuance#CRED1A_FN
     */
    public final void testIssuance_Cred1a_knownValues() {
        String credStruct = TestIssuance.CRED_STRUCT_1A;

        // loading credential structure linked to a URI
        Locations.loadCredStruct(credStruct);
        // create the issuance specification
        IssuanceSpec issuanceSpec = new IssuanceSpec(
                Locations.getIssuerId(credStruct));

        // get the values - NOTE: the values are KNOWN to both parties (as
        // specified in the credential structure)
        Values values = new Values(sp);
        values.add("attr1", ATTRIBUTE_VALUE_1);
        values.add("attr2", ATTRIBUTE_VALUE_2);
        values.add("attr3", ATTRIBUTE_VALUE_3);
        values.add("attr4", ATTRIBUTE_VALUE_4);

        // run the issuance protocol.
        Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null, values);

        Recipient recipient = new Recipient(issuanceSpec, masterSecret, values);

        Message msgToIssuer1 = recipient.round1(issuer.getNonce1());
        if (msgToIssuer1 == null) {
            fail("round1");
        }

        Message msgToRecipient2 = issuer.round2(msgToIssuer1);
        if (msgToRecipient2 == null) {
            fail("round2");
        }

        Credential cred = recipient.round3(msgToRecipient2);

        if (cred == null) {
            fail("round3");
        }

        XMLSerializer.getInstance().serialize(cred,
                Locations.getCredentialLocation(TestIssuance.CRED1A_FN));

        System.out.println(cred.toStringPretty());
    }
    /**
     * Test: Issues a credential with all implemented features.
     * 
     * @see TestIssuance#CRED_STRUCT_COMPLETE
     * @see TestIssuance#CRED_COMPLETE_FN
     */
    public final void testIssuance_Complete() {
        String credStruct = TestIssuance.CRED_STRUCT_COMPLETE;

        // reload issuer parameters with different issuer URI
        Locations.initIssuerId("http://www.ch.ch/identityCard/v2012/");
        issuerKey = Locations.getIssuerKey();

        // loading credential structure linked to a URI
        Locations.loadCredStruct(credStruct);
        Locations.loadUpdateSpecification(credStruct);
        // create the issuance specification
        IssuanceSpec issuanceSpec = new IssuanceSpec(
                Locations.getIssuerId(credStruct));

        IssuerPublicKey issuerPublicKey = issuerKey.getPublicKey();
        SystemParameters sp = issuerPublicKey.getGroupParams()
                .getSystemParams();

        // get the values for the recipient
        HashSet<String> primeEnc1 = new HashSet<String>();
        primeEnc1
                .add("CivilStatus" + Constants.DELIMITER + "Common-lawPartner");
        primeEnc1.add("OfficialLanguage" + Constants.DELIMITER + "German");
        primeEnc1.add("Gender" + Constants.DELIMITER + "Male");

        HashSet<String> primeEnc2 = new HashSet<String>();
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "B");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "B1");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "C");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "D");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "F");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "G");
        primeEnc2.add("DriverCategory" + Constants.DELIMITER + "M");

        BigInteger primeEnc1Product = Values.getPrimeEncodedProduct(
                issuanceSpec.getCredentialStructure().getAttributeStructure(
                        "primeEncoding1"), primeEnc1);
        BigInteger primeEnc2Product = Values.getPrimeEncodedProduct(
                issuanceSpec.getCredentialStructure().getAttributeStructure(
                        "primeEncoding2"), primeEnc2);

        // create an attribute based on a commitment for which the opening info
        // is available.
        CommitmentOpening comm = new CommitmentOpening(
                primeEnc2Product,
                CommitmentOpening.genRandom(issuerPublicKey.getN(), sp.getL_n()),
                issuerPublicKey);

        Values valuesRecipient = new Values(sp);
        valuesRecipient.add("PrimeEncoding1", primeEnc1Product, primeEnc1);
        valuesRecipient.add("PrimeEncoding2", comm, primeEnc2);
        valuesRecipient.add("FirstName", "Hans");
        valuesRecipient.add("LastName", "Muster");
        valuesRecipient.add("SocialSecurityNumber", ATTRIBUTE_VALUE_1);
        valuesRecipient.add("BirthDate", ATTRIBUTE_VALUE_2);
        CommitmentOpening co = new CommitmentOpening(Utils.encode(sp.getL_H(),
                "Diabetes"), CommitmentOpening.genRandom(
                issuerPublicKey.getN(), sp.getL_n()), issuerPublicKey);
        valuesRecipient.add("Diet", co);
        BigInteger currentEpoch = issuerPublicKey.computeCurrentEpoch();
        valuesRecipient.add("Epoch", currentEpoch);

        Recipient recipient = new Recipient(issuanceSpec, masterSecret,
                valuesRecipient);

        // get the values for the issuer
        Values valuesIssuer = new Values(sp);
        valuesIssuer.add("PrimeEncoding1", primeEnc1Product, primeEnc1);
        valuesIssuer.add("PrimeEncoding2", new Commitment(comm.getCommitment(),
                issuerPublicKey), primeEnc2);
        valuesIssuer.add("FirstName", "Hans");
        valuesIssuer.add("LastName", "Muster");
        valuesIssuer.add("SocialSecurityNumber", ATTRIBUTE_VALUE_1);
        valuesIssuer.add("BirthDate", ATTRIBUTE_VALUE_2);
        valuesIssuer.add("Diet", new Commitment(co.getCommitment(),
                issuerPublicKey));
        valuesIssuer.add("Epoch", currentEpoch);

        // run the issuance protocol.
        Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null,
                valuesIssuer);

        Message msgToIssuer1 = recipient.round1(issuer.getNonce1());
        if (msgToIssuer1 == null) {
            fail("round1");
        }

        Message msgToRecipient2 = issuer.round2(msgToIssuer1);
        if (msgToRecipient2 == null) {
            fail("round2");
        }

        Credential cred = recipient.round3(msgToRecipient2);

        if (cred == null) {
            fail("round3");
        }

        XMLSerializer.getInstance().serialize(cred,
                Locations.getCredentialLocation(CRED_COMPLETE_FN));

        System.out.println(cred.toStringPretty());
    }
}
