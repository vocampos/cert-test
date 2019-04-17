var forge = require('node-forge');
const fs = require('fs');

function savePrivateKey(privateKey) {
    fs.writeFileSync("./certs/private_key.cert", privateKey);
 }
 
 function saveCert(cert) {
    fs.writeFileSync("./certs/certificate.cert", cert);
 }
 
 function savePublicKey(publicKey) {
    fs.writeFileSync("./certs/public_key.cert", publicKey);
 }

var pki = forge.pki;
var keys = pki.rsa.generateKeyPair(2048);
var cert = pki.createCertificate(); // Create in X.509

cert.publicKey = keys.publicKey;
cert.serialNumber = '1234';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);

var attrs = [
    {name:'commonName',value:'site.com'}
   ,{name:'countryName',value:'BR'}
   ,{shortName:'ST',value:'Distrito Federal'}
   ,{name:'localityName',value:'Brazil'}
   ,{name:'organizationName',value:'Organization Name'}
   ,{shortName:'OU',value:'Test'}
];

cert.setSubject(attrs);

cert.setIssuer(attrs);

// signs a certificate using the given private key
cert.sign(keys.privateKey);

// convert a PEM-formatted public key to a Forge public key and cert
var pem_pkey = pki.publicKeyToPem(keys.publicKey);
savePublicKey(pem_pkey);

var pem_cert = pki.certificateToPem(cert);
saveCert(pem_cert);

var TEXT_TO_ENCRYPT = 'VALBERT CAMPOS';
// encrypt text
var pubKey = forge.pki.publicKeyFromPem(pem_pkey);
var encryptText = forge.util.encode64(pubKey.encrypt(forge.util.encodeUtf8(TEXT_TO_ENCRYPT)));
console.log("encrypt text:\n", encryptText);

// convert a PEM-formatted private key to a Forge private key and cert
var pem_prKey = pki.privateKeyToPem(keys.privateKey);
savePrivateKey(pem_prKey);

//decrypt text
let pKey = forge.pki.privateKeyFromPem(pem_prKey);
let plain = pKey.decrypt(forge.util.decode64(encryptText));

console.log("\ndecrypt text:", plain);
console.log("\ndecrypt OK?   ", plain === TEXT_TO_ENCRYPT);
console.log("\nCertificates created in the directory cert.");

