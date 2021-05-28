var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto');
var nodemailer = require('nodemailer');
var mysql = require('mysql');

// Initialization
const p = "ac0562af3c1aae9572fb9ed91991a1496a988cd1d250a48bfaf828dd149df31b";
const g = "02";
const bobDiffieHellmanGroup = crypto.createDiffieHellman(p, 'hex', g, 'hex');

// Generate a RSA key pair for Bob
const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    }
});

const bobRSAPrivateKey = keyPair["privateKey"]; 
const bobRSAPublicKey = keyPair["publicKey"];
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
var α;

var connection = mysql.createConnection({
	host     : 'localhost',
	user     : 'root',
	password : '0266',
	database : 'CEG4399_lab2'
});
connection.connect(function(err){
    if(!err) {
        console.log("Database is connected!");
    } else {
        console.log("Error connecting database!! " + err.message);
    }
});

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

app.get('/register', function(request, response) {
	response.sendFile(path.join(__dirname + '/register.html'));
});

app.post('/auth', function(request, response) {
    var username = request.body.username;
    var usernameExists = false;

    if (username != "") 
    {
        connection.query('SELECT * FROM accounts WHERE username = ?', [username], function(error, results, fields) {
            if (results.length > 0) {
                usernameExists = (results[0].username == username);
                //var email = 
                
                if (usernameExists)
                {
                    request.session.loggedin = true;
                    
                    α = Buffer.from(results[0].UserDiffieHellmanPublickey.toString(), 'hex');

                    // Generate Bob's public key β
                    β = bobDiffieHellmanGroup.generateKeys();
                    
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
                        to: results[0].email,         // List of recipients
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
                    response.send('This username does not exits!');
                }			
                response.end();
            }
        });

	} else {
        response.send('Username can\'t be blank!');
	}
});

app.get('/stage2', function(request, response) {
	response.sendFile(path.join(__dirname + '/stage2.html'));
});

app.post('/m1', function(request, response) {
    const m1 = request.body.m1;
    const iv = Buffer.from(request.body.iv, 'hex');

    // Upon recieving m1, first compute the shared secret key. using k1 and k2 to validate m1.
    const sharedSecretKey = bobDiffieHellmanGroup.computeSecret(α).toString('hex');
    const k1 = sharedSecretKey.substring(0, sharedSecretKey.length/2);
    const k2 = sharedSecretKey.substring(sharedSecretKey.length/2, sharedSecretKey.length);
    // First decrypt it using k2.
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
    if (hmac.digest('hex') == macm)
    {
        console.log("Host(Bob) uses k1 and k2 to validate m1. The result is: " + true); // Verify the mac of m.
    }
    else {
        request.session.loggedin = false;
    }

    // Bob encrypt ( mBob||MACk1(mBob) ) using the k2 and aes algorithm
    iv2 = crypto.randomBytes(16); // Initialization vector.
    const cipher = crypto.createCipheriv('aes-192-cbc', symmetricKeyFrom_k2, iv2);

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

app.post('/register', function(request, response) {
    const aliceDiffieHellmanGroup = crypto.createDiffieHellman(p, 'hex', g, 'hex');
    aliceDiffieHellmanGroup.setPrivateKey(request.body.password.toString()); // set Alice's password as the Diffie Hellman private key
    α_stored = aliceDiffieHellmanGroup.generateKeys(); // compute Alice's public key α

    connection.query('INSERT INTO accounts (username, password, email, UserDiffieHellmanPublickey) VALUES (?, ?, ?, ?);', [request.body.username, request.body.password, request.body.email, α_stored.toString('hex')], function(error, results, fields) {
        response.redirect('/');
        response.end();
    });
});

app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('m2 is: ' + m2 + '\n\nThe signature of m2 is: ' + m2_signature + '\n\nThe iv for encryption is: ' + iv2.toString('hex'));
	} else {
		response.send('m1 validation failed!');
	}
	response.end();
});

app.listen(3000);





