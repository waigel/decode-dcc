const base45 = require("base45");
var zlib = require("zlib");
const cbor = require("cbor");
const { verify, webcrypto } = require("cosette/build/sign");

const fs = require("fs");

(async function () {
  var hcertPlain = fs.readFileSync("./hcertRaw.txt").toString();
  if (!hcertPlain.startsWith("HC1:")) {
    throw new Error(
      "Input don't look like a valid hcert. String need to be start with HC1"
    );
  }
  /**
   * Remove prefix HC1:
   */
  hcertPlain = hcertPlain.substring(4);

  /**
   * Decode hcertPlain now with base45 algo
   */

  var hcertDecoded = base45.decode(hcertPlain);

  if (hcertDecoded[0] == 0x78) {
    console.log("Decompress string with zlib");
    hcertDecoded = zlib.inflateSync(hcertDecoded);
  }

  /**
   * Validate decompressed hcert should start with 0xD2
   */
  if (hcertDecoded[0] != 0xd2) {
    throw new Error("Decompressed hcert is not valid");
  }

  /**
   * Decode cbor and extract payload
   */
  const cborDecoded = cbor.decode(hcertDecoded);
  const cborPayload = cborDecoded.value[2];
  const jsonCBOR = cbor.decode(cborPayload);
  const certPayload = jsonCBOR.get(-260).get(1);
  const country = jsonCBOR.get(1);
  const iat = jsonCBOR.get(4);
  const eat = jsonCBOR.get(6);
  const coseHeader = {
    iat,
    eat,
    country,
  };

  const isSigantureValid = await validateSignature(hcertDecoded);
  console.log("Signature is:", isSigantureValid ? "VALID" : "NOT VALID");
  if (!isSigantureValid) {
    throw new Error("Signature is not valid");
  }

  /**
   * Print the certificate
   * and the hcert header
   */
  console.log("============ { HEADER } ============");
  console.log(coseHeader);
  console.log("\n============ { Payload } ============");
  console.log(certPayload);
})();

/**
 *  Validate the signature of COSE
 * return true if valid
 * @returns boolean
 *
 */
async function validateSignature(hcertDecoded) {
  let rawdata = fs.readFileSync("signing-certs.json");
  let keys = JSON.parse(rawdata);

  let cert;
  try {
    await verify(hcertDecoded, async (kid) => {
      cert = keys[kid.toString("base64")];
      return {
        key: await webcrypto.subtle.importKey(
          "spki",
          Buffer.from(cert.publicKeyPem, "base64"),
          cert.publicKeyAlgorithm,
          true,
          ["verify"]
        ),
      };
    });
    return true;
  } catch (e) {
    return false;
  }
}
