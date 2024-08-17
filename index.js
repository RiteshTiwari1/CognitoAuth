const express = require('express');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const rateLimit = require("express-rate-limit");
const { CognitoJwtVerifier } = require('aws-jwt-verify');

const app = express();
const PORT = 4002;

app.use(express.json());


AWS.config.update({ region: 'ap-south-1' });
const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();

const userPoolId = '';
const clientId = '';
const generateSecretHash = (username, clientId, clientSecret) => {
    const message = username + clientId;
    const key = clientSecret;
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(message);
    return hmac.digest('base64');
};

app.post('/register', async (req, res) => {
    console.log(req.body);
    const { name, phoneNumber, email } = req.body;

    const params = {
        "UserPoolId": userPoolId,
        // "DesiredDeliveryMediums": ['EMAIL'],
        "Username": email,
        "UserAttributes": [ 
            { Name: 'name', Value: name },
            { Name: 'phone_number', Value: phoneNumber },
            { Name: 'email', Value: email },
        ],
    };

    try {
        const x= await cognitoIdentityServiceProvider.adminCreateUser(params).promise();
        console.log(x);
        await cognitoIdentityServiceProvider.adminCreateUser({
        "UserPoolId": userPoolId,
        "DesiredDeliveryMediums": ['EMAIL'],
        "Username": email,
        "UserAttributes": [ 
            { Name: 'name', Value: name },
            { Name: 'phone_number', Value: phoneNumber },
            { Name: 'email', Value: email },
            {
                Name: 'email_verified',
                Value: 'True',
              },
              {
                Name: 'phone_number_verified',
                Value: 'True',
              },
        ],
        "MessageAction": "RESEND",
        }).promise();
        res.json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        if(error.code === "MissingRequiredParameter"){
            console.log(error.message);
        }else if(error.statusCode=== 400 && error.code === "InvalidParameterException"){
            console.log(error.message);
        }
        res.status(400).json({ message: 'Error registering user', error });
    }
});


app.post('/signin-and-change-password', async (req, res) => {
    const { username, temporaryPassword, newPassword } = req.body;

    const signInParams = {
        "AuthFlow": 'ADMIN_NO_SRP_AUTH',
        "UserPoolId": userPoolId,
        "ClientId": clientId,
        "AuthParameters": {
            USERNAME: username,
            PASSWORD: temporaryPassword,
            // SECRET_HASH: secretHash // Include SECRET_HASH in the authentication request
        },

    };

    
    try {
        // Attempt to sign in with the temporary password
        const signInResponse = await cognitoIdentityServiceProvider.adminInitiateAuth(signInParams).promise();
        console.log(signInResponse);
        if (signInResponse.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
            const { USER_ID_FOR_SRP } = signInResponse.ChallengeParameters;
            await cognitoIdentityServiceProvider.respondToAuthChallenge({
                ChallengeName: 'NEW_PASSWORD_REQUIRED',
                ClientId: clientId,
                ChallengeResponses: {
                    USERNAME: username,
                    NEW_PASSWORD: newPassword,
                    // SECRET_HASH: secretHash
                },
                Session: signInResponse.Session
            }).promise();
            
            res.json({ message: 'Password changed successfully' });
        } else {
            // Unexpected challenge, handle appropriately
            throw new Error('Unexpected challenge received');
        }
    } catch (error) {
        console.error('Error signing in and changing password:', error);
        if(error.statusCode=== 400 && error.code === "InvalidParameterException"){
            console.log(error.message);
        }
        res.status(400).json({ message: 'Error signing in and changing password', error });
    }
});




app.post('/signin', async (req, res) => {
    const { username, password } = req.body;

    try {

        const signInResponse = await cognitoIdentityServiceProvider.adminInitiateAuth({
            AuthFlow: 'ADMIN_NO_SRP_AUTH',
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
                // SECRET_HASH: secretHash 
            },
        }).promise();

        
        res.json({ messsage : "Logged in" , signInResponse});
    } catch (error) {
        
        if(error.statusCode === 400 && error.code==="NotAuthorizedException"){
            console.log(error.message);
        }
        res.status(400).json({ message: 'Error signing in', error });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { username } = req.body;

    try {

        const forgotPassword = await cognitoIdentityServiceProvider.forgotPassword({
            
            ClientId: clientId,
            Username: username,
        
            
        }).promise();

        console.log(forgotPassword);
        
        
        res.json({ forgotPassword: forgotPassword });
    } catch (error) {
        
        if(error.code === "MissingRequiredParameter"){
            console.log(error.message);
        }
        res.status(400).json({ message: 'Error signing in', error });
    }
});

app.post('/confirm-forgot-password', async (req, res) => {
    const { username , password, confirmationCode} = req.body;

    try {
        
        const resetpassword = await cognitoIdentityServiceProvider.confirmForgotPassword({
            
            ClientId: clientId,
            Username: username,
            ConfirmationCode:confirmationCode,
            Password:password
        
            
        }).promise();

        res.json({ message: "Password changed" });
    } catch (error) {

        if(error.code === "MissingRequiredParameter"){
            console.log(error.message)
        }
        res.status(400).json({ message: 'Error signing in', error });
    }
});

app.post('/register/email', async (req, res) => {
    console.log(req.body);
    const { emailID , phone_number, name} = req.body;

    const params = {
        "UserPoolId": userPoolId,
        "DesiredDeliveryMediums": ['EMAIL'],
        "Username": emailID,
        "UserAttributes": [ 
            { Name: 'email', Value: emailID },
            { Name: 'name', Value: name },
            { Name: 'phone_number', Value:  phone_number},
            { Name: 'custom:is_email_otp_enabled', Value: 'True' },
            { Name: 'custom:is_sms_otp_enabled', Value: 'True' },
            { Name: 'custom:is_wa_otp_enabled', Value: 'True'},
            { Name: 'custom:isd_code', Value:"+91"},
        ],
    };

    try {
        const x = await cognitoIdentityServiceProvider.adminCreateUser(params).promise();
        console.log(x);
        await cognitoIdentityServiceProvider.adminCreateUser({
        "UserPoolId": userPoolId,
        "DesiredDeliveryMediums": ['EMAIL'],
        "Username": emailID,
        "UserAttributes": [ 
            { Name: 'email', Value: emailID },
            { Name: 'name', Value: name },
            { Name: 'phone_number', Value:  phone_number},
            {
                Name: 'email_verified',
                Value: 'True',
            },
            {
                Name: 'phone_number_verified',
                Value: 'True',
            },
        ],
        "MessageAction": "RESEND",
        }).promise();
        res.json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(400).json({ message: 'Error registering user', error });
    }
});


const blockedIPs = new Map();

const checkBlockedIP = (req, res, next) => {
    const clientIP = req.ip;
    
    console.log("hello");
    if (blockedIPs.has(clientIP)) {
        const currentTime = new Date().toLocaleTimeString();

        console.log("Current time:", currentTime);
        return res.status(429).json({ message: "Too many requests from this IP, please try again later" });
    }
    next();
};

const limiter = rateLimit({

    windowMs: 60 * 1000, // 1 minute
    max: 5, // limit each IP to 100 requests per windowMs
    message : async (req, res) => {
        const clientIP = req.ip;
        // Block the IP for 2 minutes
        blockedIPs.set(clientIP, true);
        setTimeout(() => {
            blockedIPs.delete(clientIP);
        }, 3 * 60 * 1000); // Unblock after 2 minutes
        return "Too many requests from this IP, please try again later ........"
    }
});


app.patch('/user/edit', async(req,res) =>{
    console.log(req.body);
    const { emailID } = req.body;

    const params = {
        "UserPoolId": userPoolId,
        "Username": emailID,
        "UserAttributes": [ 
            { Name: 'custom:is_email_otp_enabled', Value: 'False' },
            { Name: 'custom:is_sms_otp_enabled', Value: 'True' },
            { Name: 'custom:is_wa_otp_enabled', Value: 'False' },
        ],
    };

    try {
        const x = await cognitoIdentityServiceProvider.adminUpdateUserAttributes(params).promise();
        console.log(x);
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(400).json({ message: 'Error Updating user', error });
    }
})

app.post('/signin/email', checkBlockedIP ,limiter, async (req, res, next) => {

    const clientIP = req.ip;
    if (blockedIPs.has(clientIP)) {
        console.log("hello");
        return res.status(429).json({ message: "Too many requests from this IP, please try again later" });
    }

    const { emailID } = req.body; 
    const clientSecret = '9kvvt1a09dbt47nah9gqhmc6q349b1m7p1gbaf5ivvrfm00v9jk';
    const secretHash = generateSecretHash(emailID, clientId, clientSecret);
    
    try {
        const data = await cognitoIdentityServiceProvider.initiateAuth({
            AuthFlow: 'CUSTOM_AUTH',
            ClientId: clientId,
            AuthParameters: { 
                USERNAME: emailID, 
            },
            ClientMetadata: {
                "abc":"1",
            },
            UserContextData: {
                "EncodedData": clientSecret,
            }
        }).promise();
        
        const sessionToken = data.Session; // Store session token for subsequent challenge response
        res.json({ message: 'Authentication initiated successfully', sessionToken });
    } catch (error) {
        console.error('Error initiating authentication:', error);
        res.status(error.statusCode || 400).json({ message: 'Error initiating authentication', error: error.message });
    }
});



app.post('/signin/email-otp', async (req, res) => {
    try {
        const { emailID, otp, session } = req.body;
        cognitoIdentityServiceProvider.respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: session,
            ChallengeResponses: {
                USERNAME: emailID,
                ANSWER: otp,
                // SECRET_HASH: secretHash
            }
        }, async (error, data) => {
            if (error) {

                console.log("121")
                console.error('Error:', error);
                
                res.status(400).json({ message: 'Error signing in', error: error.message });
            } else {
                console.log('Authentication Response:', data);
                res.json({ data });
            }
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred during sign-in', error: error.message });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

async function verify(data) {
    const idTokenVerifier = CognitoJwtVerifier.create({
        userPoolId: userPoolId,
        tokenUse: 'id',
        clientId: clientId,
    });

    try {
        const payload = await idTokenVerifier.verify(
            data // Assuming idToken is a property of the data object
        );
        // Handle the verified payload here
        console.log(payload);
    } catch (err) {
        console.log(err);
    }
}