const crypto = require('crypto');
var readlineSync = require('readline-sync');

//Initialization
const p = "ac0562af3c1aae9572fb9ed91991a1496a988cd1d250a48bfaf828dd149df31b";
const g = "02";
var bobRSAPublicKey;

fs = require('fs');
try 
{
    const data = fs.readFileSync('Bob_RSApublickey.txt', 'utf8');
    bobRSAPublicKey = data;
}
catch (err)  
{  
    console.log(err);
}








const β = readlineSync.question("Please enter the verification code you recieved from email: ");
const alice_privateKey = readlineSync.question("Please also enter your Password: ");

const aliceDiffieHellmanGroup = crypto.createDiffieHellman(p, 'hex', g, 'hex');
aliceDiffieHellmanGroup.setPrivateKey(alice_privateKey);
const α = aliceDiffieHellmanGroup.generateKeys(); // compute Alice's public key using the password(the private key), p and g.
const sharedSecretKey = aliceDiffieHellmanGroup.computeSecret(Buffer.from(β, 'hex')).toString('hex');
const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);

const m = α + β;
const hmac = crypto.createHmac('sha256', k1);
hmac.update(m);

// Alice encrypt ( m||MACk1(m) ) using the k2 and aes algorithm
const algorithm = 'aes-192-cbc';
const symmetricKeyFrom_k2 = crypto.scryptSync(k2, "salt", 24); // keylen:24
const iv = crypto.randomBytes(16); // Initialization vector.
const cipher = crypto.createCipheriv('aes-192-cbc', symmetricKeyFrom_k2, iv);

var m1 = cipher.update(m + ";;;;" + hmac.digest('hex'), 'utf8', 'hex');
m1 += cipher.final('hex');

console.log("\nThe computed m1 is: " + m1 + " \nThe initialization vector(iv) is: " + iv.toString('hex') + "\nPlease enter them in the login screen.");







const m2 = readlineSync.question("\nPlease enter m2: ");
const signature_m2 = readlineSync.question("Please enter the signature of m2: ");
const iv2 = readlineSync.question("Please enter iv that used to encrypt the m2: ");

// Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob. 
const verify = crypto.createVerify('SHA256');
verify.write(m2);
verify.end();
const isVerifiedSignature = verify.verify(bobRSAPublicKey, signature_m2, 'hex');
console.log("Verifies the digital signature: " + isVerifiedSignature);

// Validate mac of m'
// First decrypt it using the shared secret key.
const decipher = crypto.createDecipheriv('aes-192-cbc', symmetricKeyFrom_k2, Buffer.from(iv2, 'hex'));

var decrypted_m2 = decipher.update(m2, 'hex', 'utf8');
decrypted_m2 += decipher.final('utf8');

const mAndMacm = decrypted_m2.split(";;;;");
const mBob = mAndMacm[0];
const macmBob = mAndMacm[1];
const hmac2 = crypto.createHmac('sha256', k1);
hmac2.update(mBob);
const isVerifiedMac = (hmac2.digest('hex') == macmBob);
console.log("\nVerify the mac of mBob: " + isVerifiedMac); // Verify the mac of mBob.


if (isVerifiedSignature && isVerifiedMac)
{
    console.log("\nSuccess!");
}
