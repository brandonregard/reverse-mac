'use strict';

/**
 * Generates a policy to allow our authorizer to execute the reverse_mac lambda
 * @param effect
 * @param resource
 * @returns {{policyDocument: {Version: string, Statement: [{Action: string, Resource: *, Effect: *}]}, principalId: string}}
 */
const generatePolicy = (effect, resource) => {

    return {
        principalId: '*',
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource,
            }],
        },
    };
};

/**
 * Makes sure we a passed a bearer token in the correct format and time frame
 * @param bearerToken
 * @returns {boolean}
 */
const validateToken = (bearerToken) => {

    if (bearerToken.indexOf('Bearer') === 0) {
        const token = bearerToken.substring(7, bearerToken.length);
        const date = parseInt(token.substring(0, token.length / 2));
        const now = Date.now();
        const tenMinutes = 600000;

        return ((date <= (now + tenMinutes)) && (date >= (now - tenMinutes)));
    } else {
        return false;
    }
};

/**
 * Add delimiters to a mac address that doesn't have any
 * @param mac
 * @returns {string}
 */
const addMacDelimiters = (mac) => {
    let result = '';

    for (let c = 0; c < mac.length; c++) {
        result += mac[c];

        if ((c + 1) % 2 === 0) {
            result += ':';
        }
    }

    return result.substring(0, result.length - 1);
};

/**
 * Reverse a list of mac addresses in valid formats and supply errors for incorrectly formatted macs
 * @param macs
 */
const reverse = (macs) => {
    let result = {};
    const revMacs = [];
    const errMacs = [];
    const regex1 = RegExp('^([0-9A-F]{12})$');
    const regex2 = RegExp('^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$');
    const regex3 = RegExp('^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$');

    for (let mac of macs) {

        if (regex1.test(mac)) {
            mac = addMacDelimiters(mac);
            revMacs.push(mac.split(':').reverse().join(''));
        } else if (regex2.test(mac)) {
            revMacs.push(mac.split(':').reverse().join(':'));
        } else if (regex3.test(mac)) {
            revMacs.push(mac.split('-').reverse().join('-'));
        } else {
            errMacs.push({mac: mac, error: 'Invalid format.'});
        }
    }

    if (revMacs.length) {
        result["reversed-macs"] = revMacs;
    }

    if (errMacs.length) {
        result["error"] = errMacs;
    }

    return result;
};

/**
 * authorizeHandler to validate our token and generate generate a policy that will allow reverse_mac invocation
 * @param event
 * @returns {Promise<{policyDocument: {Version: string, Statement: {Action: string, Resource: *, Effect: *}[]}, principalId: string}>}
 */
module.exports.authorize = async event => {

    if (event.authorizationToken === 'undefined') {
        return generatePolicy('Deny', event.methodArn);
    }

    if (validateToken(event.authorizationToken)) {
        return generatePolicy('Allow', event.methodArn);
    } else {
        return generatePolicy('Deny', event.methodArn);
    }
};

/**
 * reverseMacHandler
 * @param event
 * @returns {Promise<{body: string, statusCode: number}|{body: *, statusCode: number}>}
 */
module.exports.reverseMac = async event => {

    try {
        let result = reverse(JSON.parse(event.body)['macs']);

        return {
            statusCode: 200,
            body: JSON.stringify(result, null, 2),
        };
    } catch (e) {

        return {
            statusCode: 500,
            body: e.message,
        };
    }
};

/**
 * Exports for tests
 */
module.exports.reverse = reverse;
module.exports.validateToken = validateToken;
