var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto');
var nodemailer = require('nodemailer');

// Initialization
const p = "ac0562af3c1aae9572fb9ed91991a1496a988cd1d250a48bfaf828dd149df31b";
const g = "02";
const alice = crypto.createDiffieHellman(p, 'hex', g, 'hex');
const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
alice.setPrivateKey("098765"); // Alice's password is 098765
const α = alice.generateKeys(); // this is Alice's public key α stored at Host Bob
const aliceUsername = "a";
const aliceEmail = "pjylost@gmail.com";

// Generate a RSA key pair for Bob
const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    }
});

const bobRSAPrivateKey = keyPair["privateKey"];//"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIj/osdBEKpSUCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBAQNYLStja8tRacS3AURx3BIIE0JAB0MutQdP1lVo/KX2MVULcpyxpR9uEP9edj0qrzPR+qRGZF3pGrWArbI+y5ZAPlJ4BethcFXilpnQyZriXVn16EclX8j3FJQGRzKz9IDPlcG0UdnZQqT2Duc4zFynp1l+vFtL3GQx1meGzYm5KAYyWhQdZxgHFR/8q6VWr0ZOWXaD1ufsZXkyH3tUt7EXnA74nOFG0CSFdRFrWiedBKHGQRaeW+azUq+7fXXHSdReqP4Ri4VJWzlsAcRQ8G+KSh7XZyP25bQ/m4urwKzPVrHi8EZOyI8NKUDe0LdBiQ0Je/gBnSvaYfoK6Gm69VgpefAt1pt7BqPjqObtideOeTW/x+b7s6c/t3WyRjkrH0KS7QYrpokUC4JFxQ9PtljkJm5wz83YiXnjfQ/PtTzIagVX2RgXxAjBLP+JJaTuCxCeKxJ0XUH9QAZ+4jYByZ2NmQbufXK8WnysBpwogULOIjxBZRVaZFqWXWp+wLXdPqCFy83GfQJZrqJnVIzsTlU100+piSMb6jgSj41BN0VNn/Y8e9MLvl8shnHnFf7wXUnRLC75FJvseSONUupQvPEVE7ElNFYCfVsOXpvoVdjs1By7a7nTZyjie645Wbj8nLThnhfXxmeXC89HvIwXPkrSPJm2+XCc9kQDz6zWE6odTU7yr2ZL52pmoXtVmDuj0q03mtt2WfmzoruiTYldUFiB3vBmtrtdUNBZuPNw5fC0R9VB5tIE6g4CwQw0iDa624OKucxCDNQMQ95fSDrDhnk2ZM2wCk6Q73DJ+9CKWYBtvRd/jIFO0Gx20weuIdGHx9r0wMKUGcr4DDU6ol2OPk41py6L6MrBO+3XjcZRyBX7fZFTWfhaquWYwToTWkTWAJa6zMrQHc/jYqHS9kdNYLtyFq44+LHieAd0eeBYSf8E9v7T+Qlgx7VLcV7yKqqkH6R/4nVp5ROXZg145Z03IKuDoyZDhgZLN7vTeDhr2tELhIWqoAUlrZICUx2VaIfw1VajEx/i66ml6/NVE+STj69eS9S/vd/rM2S9k/Ae/wCQrNzIJHV/BjeZ+0yeaMRFcgQJQAW5qT1mWFRouWjOhPBP/BjVAG5YX0y18V/yxXnwgNQvcWqZQANBlJ/GNNCuwMr/az4MA2/nKahzVXHOZO2hW6a9dyWCUgjGfXKmFUJWNHHTyEkRNZgiUvjGQ9MvCPWi+spavNujGvv3z6wLPSvVowTzQUWt2ag2T+Tem0KlACWUieYEiEvEJLD8HY82lo8TnJmTfxBgQyTmAA1puG9h1sMMeR+mzRSht/wXwBhcD92xQPP6dyfqAxv491njpwo7t5rL1O0Xiisecuq4kt7+u1a6YYedjnccq89WgKHVcT3BpXVHa1XwNruoscnT1zQTS968hbHnu490HNL99Qq5Nl6A1ij4EpTOZa0nWQOuo+/ZIJwE8lliShGei0fb6wOfLiD3P7ls5MuqzHcLvWq83AwQDGCgipW6kUxL+rW9H1dd4jJzXP8p7T8E4gAPD6kUGhQb+WNEooZL6pkKVd12Qn6yAU0uHUmaBx682tGyjD7AQ2yeiAiqGHkYTJcw6TA9YFJDQyVMmPmGXjNXb7dvxdnWZl55GXC1wr7q9qagBSInxKpOwxSYl6Sbyeo+R45cy"//keyPair["privateKey"];
const bobRSAPublicKey = keyPair["publicKey"];//"MIIBCgKCAQEA6z+giA6hDuF1jC1eCNW+nKbZgRw5R3L0BYIa2mbqN2owV/fNG+rWScP+82e/cR/YLAtBZp/nxubDKUN4QBrJh9XEIpa+Fnh8P6U8PEFVXKGvhaComF5PVXMLn2t1A4L78ZfaPvf5X/4NOy1Y2WhWOyKy68Yd/tV4J1ZK2ArYt9pJw88x7C57SyRXqI563VWZKA2Z/F87EaucoB78+srh+DUXMNmB22hJoqdd+cDsJO+G/L6U+gk9JPMWPgCekW95qJNd1mhaqkF2P35HvFIP2nlY+6eXAMRr7onC/c/8AQ9Pj6JWrHKb11ZpKmnXAHh7/us/H/3xB2LEsiDbskQk7QIDAQAB"//keyPair["publicKey"]; 
// Give bobRSAPublicKey to Alice
fs = require('fs');
fs.writeFile('Bob_RSApublickey.txt', bobRSAPublicKey, function (err) {
  if (err) return console.log(err);
  console.log('Initialization Succeed!');
});
var m2;
var m2_signature;
var β; 
var iv2;


var app = express();

app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));
app.use(bodyParser.urlencoded({extended : true}));
app.use(bodyParser.json());

app.get('/', function(request, response) {
	response.sendFile(path.join(__dirname + '/login.html'));
});

app.post('/auth', function(request, response) {
    var username = request.body.username;
    
    if (username != "") 
    {
        if (username == aliceUsername)
        {
            request.session.loggedin = true;
            
            // Generate Bob's public key β
            β = bob.generateKeys();
            //console.log(β.toString('hex'));
            
            // Host(Bob) send his public key(β) as an email(or SMS text) message to Alice
            let transport = nodemailer.createTransport({
                host: 'smtp.mailtrap.io',
                port: 2525,
                auth: {
                   user: 'dd4bfb165af770',
                   pass: 'a8e8d1dad518b2'
                }
            })
            
            const message = {
                from: 'pjylost@gmail.com', // Sender address
                to: 'jpan080@uottawa.ca',         // List of recipients
                subject: 'CEG4399 Lab2 Login Verification (Bob\'s Diffie Hellman public key β)', // Subject line
                text: β.toString('hex') // Plain text body
            };
            transport.sendMail(message, function(err, info) {
                if (err) {
                  console.log(err)
                } else {
                  console.log("Successfully send the email!");
                }
            });
            
            //response.sendFile(path.join(__dirname + '/stage2.html'));

            response.redirect('/stage2');
        } else {
            response.send('Incorrect Username and/or Password!');
        }			
        response.end();
	} else {
       
	}
});

app.get('/stage2', function(request, response) {
	response.sendFile(path.join(__dirname + '/stage2.html'));
});

app.post('/m1', function(request, response) {
    const m1 = request.body.m1;
    const iv = Buffer.from(request.body.iv, 'hex');

    // Upon recieving m1, first compute the shared secret key. using k1 and k2 to validate m1.
    const sharedSecretKey = bob.computeSecret(α, null, 'hex').toString('hex');
    const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
    const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);
    // First decrypt it using the shared secret key.
    const algorithm = 'aes-192-cbc';
    const symmetricKeyFrom_k2 = crypto.scryptSync(k2, "salt", 24); // keylen:24
    const decipher = crypto.createDecipheriv(algorithm, symmetricKeyFrom_k2, iv);

    var decrypted_m1 = decipher.update(m1, 'hex', 'utf8');
    decrypted_m1 += decipher.final('utf8');

    const mAndMacm = decrypted_m1.split(";;;;");
    const m = mAndMacm[0];
    const macm = mAndMacm[1];
    const hmac = crypto.createHmac('sha256', k1);
    hmac.update(m);
    //hmac.update(m + hmac.digest('hex'));
    if (hmac.digest('hex') == macm)
    {
        console.log("Host(Bob) uses k1 and k2 to validate m1. The result is: " + true); // Verify the mac of m.
    }
    else {
        request.session.loggedin = false;
        //response.redirect('/home')
    }

    // Bob encrypt ( mBob||MACk1(mBob) ) using the k2 and aes algorithm
    iv2 = crypto.randomBytes(16); // Initialization vector.
    const cipher = crypto.createCipheriv(algorithm, symmetricKeyFrom_k2, iv2);

    const mBob = β + α;
    const hmac2 = crypto.createHmac('sha256', k1);
    hmac2.update(mBob);
    m2 = cipher.update(mBob + ";;;;" + hmac2.digest('hex'), 'utf8', 'hex');
    m2 += cipher.final('hex');

    // Bob signs the m2 using his private key.
    const sign = crypto.createSign('SHA256');
    sign.write(m2);
    sign.end();
    m2_signature = sign.sign(bobRSAPrivateKey, 'hex');
    // Bob sends this m2, iv2 and signature of m2 to Alice's login screen

    response.redirect('/home');
    response.end();
    
});

app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('m2 is: ' + m2 + '. signature of m2 is: ' + m2_signature + '\nThe iv for encryption is: ' + iv2.toString('hex'));
	} else {
		response.send('m1 validation failed!');
	}
	response.end();
});

app.listen(3000);







// const assert = require('assert');

// const AliceUsername = "a";
// const AliceEmail = "pjylost@gmail.com";

// // System parameter p and a, which is known to everyone
// // const p = "fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17"; // 353;
// // const g = "678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4"//3;

// // const α = 40;

// // Generate Alice's keys...
// //const alice = crypto.getDiffieHellman('modp14'); //create a predefined DiffieHellmanGroup key exchange object with predefined 2048 bits prime number and generator.
// const alice = crypto.createDiffieHellman(1024);
// alice.setPrivateKey("098765"); // Alice's password is 098765
// //alice.generateKeys(); // Generates random private and public Diffie-Hellman key values
// const α = alice.generateKeys(); // this is Alice's public key α stored at Host Bob.

// // Create a RSA key pair
// const keyPair = crypto.generateKeyPairSync('rsa', {
//     modulusLength: 2048,
// });

// const bobPrivateKey = keyPair["privateKey"];
// const bobPublicKey = keyPair["publicKey"]; // Give it to Alice

// // const p = alice.getPrime();
// // const g = alice.getGenerator();
// // console.log("Alice's password α: " + alicePublicKey.toString('hex'));
// // The host Bob stores Alice's password α with Alice's username and phone number;










// // Get Alice's username
// // Generate Bob's keys...
// const bob = crypto.getDiffieHellman('modp14'); // crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
// //const β = bob.generateKeys(); // Host(Bob) send his public key(β) as an SMS text message to Alice

// bob.generateKeys();// Generates random private and public Diffie-Hellman key values
// const β = bob.getPublicKey();

// // Host(Bob) send his public key(β) as an SMS text message to Alice
// let transport = nodemailer.createTransport({
//     host: 'smtp.mailtrap.io',
//     port: 2525,
//     auth: {
//        user: 'dd4bfb165af770',
//        pass: 'a8e8d1dad518b2'
//     }
// })

// const message = {
//     from: 'jpan080@uottawa.ca', // Sender address
//     to: 'pjylost@gmail.com',         // List of recipients
//     subject: 'CEG4399 Lab2 Login Verification', // Subject line
//     text: β // Plain text body
// };
// transport.sendMail(message, function(err, info) {
//     if (err) {
//       console.log(err)
//     } else {
//       console.log(info);
//     }
// });

// const m1;
// const iv;
// // Upon recieving m1, first compute the shared secret key. using k1 and k2 to validate m1.
// const sharedSecretKey = bob.computeSecret(alice.getPublicKey(), null, 'hex').toString('hex');
// const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
// const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);
// // First decrypt it using the shared secret key.
// const algorithm = 'aes-192-cbc';
// const decipher = crypto.createDecipheriv(algorithm, sharedSecretKey, iv);

// var decrypted_m1 = decipher.update(m1, 'hex', 'utf8');
// decrypted_m1 += decipher.final('utf8');

// const mAndMacm = decrypted_m1.split(";;;;");
// const m = mAndMacm[0];
// const macm = mAndMacm[1];
// const hmac = crypto.createHmac('sha256', k1);
// hmac.update(m);
// //hmac.update(m + hmac.digest('hex'));
// console.log(hmac.digest('hex') == macm); // Verify the mac of m.

// // Bob encrypt ( mBob||MACk1(mBob) ) using the k2 and aes algorithm
// const algorithm = 'aes-192-cbc';
// const iv2 = crypto.randomBytes(16); // Initialization vector.
// const cipher = crypto.createCipheriv(algorithm, k2, iv2);

// const mBob = β + α;
// var m2 = cipher.update(mBob + ";;;;" + hmac.digest('hex'), 'utf8', 'hex');
// m2 += cipher.final('hex');

// // Bob signs the m2 using his private key.
// const sign = crypto.createSign('SHA256');
// sign.write(m2);
// sign.end();
// const signature = sign.sign(bobPrivateKey, 'hex');
// // Bob sends this m2, iv2 and signature of m2 to Alice's login screen











// // Exchange and generate the shared secret...
// const aliceSecret = alice.computeSecret(bobPublicKey);
// const bobSecret = bob.computeSecret(alicePublicKey); 

// // Verify aliceSecret is equal to bobSecret
// //assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
// const sharedSecretKey = aliceSecret.toString('hex');
// console.log(aliceSecret.toString('hex'));

// //Alice's local application
// const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
// const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);

// const m = α + β;
// const hmac = crypto.createHmac('sha256', k1);
// hmac.update(m);
// console.log(hmac.digest('hex'));


// // Alice encrypt ( m||MACk1(m) ) using the k2 and aes algorithm
// // const hamc2 = crypto.createHmac('sha256', k2);
// // hmac2.update(m + hmac.digest('hex'));
// // m1 = hmac2.digest('hex')
// // console.log(hmac2.digest('hex')); 
// // Alice sends m1 and password α to Bob throught the login screen

// // Alice encrypt ( m||MACk1(m) ) using the k2 and aes algorithm
// const algorithm = 'aes-192-cbc';
// const iv = crypto.randomBytes(16); // Initialization vector.
// const cipher = crypto.createCipheriv(algorithm, k2, iv);

// var m1 = cipher.update(m + ";;;;" + hmac.digest('hex'), 'utf8', 'hex');
// m1 += cipher.final('hex');
// // Alice sends m1 and password α to Bob throught the login screen


// // Bob validate m1 using k1,k2 and authenticate Alice.
// hmac.update(m);
// hmac2.update(m + hmac.digest('hex'));
// console.log(hmac2.digest('hex') == hmac2.digest('hex'));
// // const decipher = crypto.createDecipheriv(algorithm, sharedSecretKey, iv);

// // let decryptedm1 = decipher.update(m1, 'hex', 'utf8');
// // decryptedm1 += decipher.final('utf8');


// mBob = bobPublicKey + alicePublicKey;
// hmac.update(mBob);
// console.log(hmac.digest('hex'));
// // Bob encrypt ( mBob||MACk1(mBob) ) using the shared key
// const algorithm = 'aes-192-cbc';
// const password = 'Password used to generate key';//readlineSync.question('Bob, enter the password you want to use to generate the symmetric key: '); // Password used to generate key
// const salt = crypto.randomBytes(32);
// const symmetricKey = crypto.scryptSync(password, salt, 24); // keylen:24

// const iv = crypto.randomBytes(16); // Initialization vector.

// const cipher = crypto.createCipheriv(algorithm, sharedSecretKey, iv);

// var m2 = cipher.update(mBob + hmac.digest('hex'), 'utf8', 'hex');
// m2 += cipher.final('hex');


// m2 = mBob + hmac.digest('hex');



// const keyPair = crypto.generateKeyPairSync('rsa', {
//     modulusLength: 2048,
// });

// const bobPrivateKey = keyPair["privateKey"];
// const bobPublicKey = keyPair["publicKey"];

// // Bob signs the m2 using his private key.
// const sign = crypto.createSign('SHA256');
// sign.write(m2);
// sign.end();
// const signature = sign.sign(bobPrivateKey, 'hex');
// // Bob sends this m2 and signature of m2 to Alice's login screen

// // Alice steps
// // Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob. 
// const verify = crypto.createVerify('SHA256');
// verify.write(m2);
// verify.end();
// const isVerified = verify.verify(bobPublicKey, signature, 'hex');


//console.log(aliceKey);

// const alpha = 17;
// const q = 109;
// const XA = 99; // Alice password
// const XB = 71;

// const YA = Math.pow(alpha, XA) % q;
// const YB = Math.pow(alpha, XB) % q;

// const keyByAlice = Math.pow(YB, XA) % q;
// const k1 = 
// const keyByBob = Math.pow(YA, XB) % q;
// // Alice enter YB and password 99 to a local application and calculate the key.
// const m1 = 


// // Bob signs the doocument using his private key.
// const sign = crypto.createSign('SHA256');
// sign.write(encryptedSymmetricKey.toString('hex'));
// sign.end();
// const signature = sign.sign(bobPrivateKey, 'hex');


// // Alice steps
// // Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob. 
// const verify = crypto.createVerify('SHA256');
// verify.write(encryptedSymmetricKey.toString('hex'));
// verify.end();
// const isVerified = verify.verify(bobPublicKey, signature, 'hex');

// console.log(verify.verify(publicKey, signature, 'hex'));
// // Prints: true