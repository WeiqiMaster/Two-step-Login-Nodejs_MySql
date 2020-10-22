const crypto = require('crypto');
var readlineSync = require('readline-sync');

//Initialization
const p = "ac0562af3c1aae9572fb9ed91991a1496a988cd1d250a48bfaf828dd149df31b";
const g = "02";
const alice = crypto.createDiffieHellman(p, 'hex', g, 'hex');
var bobRSAPublicKey;// = "MIIBCgKCAQEA6z+giA6hDuF1jC1eCNW+nKbZgRw5R3L0BYIa2mbqN2owV/fNG+rWScP+82e/cR/YLAtBZp/nxubDKUN4QBrJh9XEIpa+Fnh8P6U8PEFVXKGvhaComF5PVXMLn2t1A4L78ZfaPvf5X/4NOy1Y2WhWOyKy68Yd/tV4J1ZK2ArYt9pJw88x7C57SyRXqI563VWZKA2Z/F87EaucoB78+srh+DUXMNmB22hJoqdd+cDsJO+G/L6U+gk9JPMWPgCekW95qJNd1mhaqkF2P35HvFIP2nlY+6eXAMRr7onC/c/8AQ9Pj6JWrHKb11ZpKmnXAHh7/us/H/3xB2LEsiDbskQk7QIDAQAB";
fs = require('fs');

try 
{
    const data = fs.readFileSync('Bob_RSApublickey.txt', 'utf8');
    bobRSAPublicKey = data;
    //console.log(bobRSAPublicKey);
}
catch (err)  
{  
    console.log(err);
}
alice.setPrivateKey("098765"); // Alice's password is 098765








const β = readlineSync.question("Please enter the β you recieved from email: ");
const alice_privateKey = readlineSync.question("Please also enter your Password: ");

alice.setPrivateKey(alice_privateKey);
const α = alice.generateKeys(); // this is Alice's public key α stored at Host Bob
const sharedSecretKey = alice.computeSecret(Buffer.from(β, 'hex')).toString('hex');
//console.log(sharedSecretKey);
//console.log(Math.pow(parseInt(β, 16), alice_privateKey) % alice.getPrime());
const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);

const m = α + β;
const hmac = crypto.createHmac('sha256', k1);
hmac.update(m);

// Alice encrypt ( m||MACk1(m) ) using the k2 and aes algorithm
const algorithm = 'aes-192-cbc';
// const salt = crypto.randomBytes(32);
const symmetricKeyFrom_k2 = crypto.scryptSync(k2, "salt", 24); // keylen:24
const iv = crypto.randomBytes(16); // Initialization vector.
const cipher = crypto.createCipheriv(algorithm, symmetricKeyFrom_k2, iv); //createCipher(algorithm, k2); //

var m1 = cipher.update(m + ";;;;" + hmac.digest('hex'), 'utf8', 'hex');
m1 += cipher.final('hex');

console.log("\nThe computed m1 is: " + m1 + " \nThe initialization vector(iv) is: " + iv.toString('hex') + "\nPlease enter them in the login screen.");







const m2 = readlineSync.question("\nPlease enter m2: ");
const signature_m2 = readlineSync.question("Please enter the signature of m2: ");
const iv2 = readlineSync.question("Please enter iv that used to encrypt the m2: ");

// Validate m2

// Upon recieving m1, first compute the shared secret key. using k1 and k2 to validate m1.
// First decrypt it using the shared secret key.
const decipher = crypto.createDecipheriv(algorithm, symmetricKeyFrom_k2, Buffer.from(iv2, 'hex'));

var decrypted_m2 = decipher.update(m2, 'hex', 'utf8');
decrypted_m2 += decipher.final('utf8');

const mAndMacm = decrypted_m2.split(";;;;");
const mBob = mAndMacm[0];
const macmBob = mAndMacm[1];
const hmac2 = crypto.createHmac('sha256', k1);
hmac2.update(mBob);
console.log("ggggggggggggg");
console.log("\nVerify the mac of mBob: " + (hmac2.digest('hex') == macmBob)); // Verify the mac of mBob.



// Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob. 
const verify = crypto.createVerify('SHA256');
verify.write(m2);
verify.end();
const isVerified = verify.verify(bobRSAPublicKey, signature_m2, 'hex');
console.log("Verifies the digital signature: " + isVerified);
console.log("\nSuccess!");














// const β = readlineSync.question("Alice, enter the verification code β (Bob's public key) you recieved from the host Bob:");

// // Alice encrypt ( m||MACk1(m) ) using the k2 and aes algorithm
// const algorithm = 'aes-192-cbc';
// const iv = crypto.randomBytes(16); // Initialization vector.
// const cipher = crypto.createCipheriv(algorithm, k2, iv);

// var m1 = cipher.update(m + ";;;;" + hmac.digest('hex'), 'utf8', 'hex');
// m1 += cipher.final('hex');

// console.log("The computed m1 is: " + m1 + ". The initialization vector(iv) is: " + iv + "Please enter it into the login screen");
// // Alice input m1 and initialization vector(iv) to Bob through the login screen