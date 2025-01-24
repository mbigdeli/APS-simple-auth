const {Scopes} = require('@aps_sdk/authentication');
require('dotenv').config();


// could this let be const or not? we have to test it later

let {
    APS_CLIENT_ID,
    APS_CLIENT_SECRET,
    APS_CALLBACK_URL,
    SERVER_SESSION_SECRET,
    PORT
} = process.env;

if (!APS_CLIENT_ID || !APS_CLIENT_SECRET || !APS_CALLBACK_URL || !SERVER_SESSION_SECRET || !PORT) {
    console.error('Missing environment variables');
    process.exit(1);
};

const INTERNAL_TOKEN_SCOPES = [Scopes.DataRead, Scopes.ViewablesRead];
const PUBLIC_TOKEN_SCOPES = [Scopes.ViewablesRead];
PORT = PORT || 8080;

module.exports = {
    APS_CLIENT_ID,
    APS_CLIENT_SECRET,
    APS_CALLBACK_URL,
    SERVER_SESSION_SECRET,
    PORT,
    INTERNAL_TOKEN_SCOPES,
    PUBLIC_TOKEN_SCOPES
};

