const OAuth = require("oauth-1.0a");
const { createHmac } = require("crypto");
const got = require("got");
const querystring = require("querystring");

class NetSuiteRest {
  constructor({ consumerKey, consumerSecret, token, tokenSecret, accountId }) {
    this.accountId = accountId;
    this.consumerKey = consumerKey;
    this.consumerSecret = consumerSecret;
    this.token = token;
    this.tokenSecret = tokenSecret;
  }

  getAuthorizationHeader({ url, method }) {
    const oauth = OAuth({
      consumer: { key: this.consumerKey, secret: this.consumerSecret },
      signature_method: "HMAC-SHA256",
      realm: this.accountId,
      hash_function(base_string, key) {
        return createHmac("sha256", key).update(base_string).digest("base64");
      },
    });

    const signedData = oauth.authorize(
      {
        url,
        method,
      },
      {
        key: this.token,
        secret: this.tokenSecret,
      }
    );

    return oauth.toHeader(signedData).Authorization;
  }

  getAccountPath() {
    return this.accountId.toLowerCase().replace("_", "-");
  }

  async request({ body, path, method = "GET", options = {} }) {
    const accountPath = this.getAccountPath();
    const url = `https://${accountPath}.suitetalk.api.netsuite.com/services/rest/record/v1${path}`;
    const authorization = this.getAuthorizationHeader({ url, method });

    try {
      const res = await got(url, {
        method,
        json: body,
        responseType: "json",
        headers: { Authorization: authorization },
        ...options,
      });

      return res.body;
    } catch (err) {
      if (err.response) {
        console.log(err.response.body);
        return err.response.body;
      } else {
        throw err;
      }
    }
  }

  async restlet({
    body,
    method = "GET",
    deployId = "1",
    scriptId,
    options = {},
  }) {
    const accountPath = this.accountId.toLowerCase().replace("_", "-");
    const url = `https://${accountPath}.restlets.api.netsuite.com/app/site/hosting/restlet.nl?deploy=${deployId}&script=${scriptId}`;
    const authorization = this.getAuthorizationHeader({ url, method });

    try {
      const res = await got(url, {
        method,
        json: body,
        responseType: "json",
        headers: { Authorization: authorization },
        ...options,
      });

      return res.body;
    } catch (err) {
      if (err.response) {
        console.log(err.response.body);
        return err.response.body;
      } else {
        throw err;
      }
    }
  }

  async suiteql(query, options = {}) {
    const { query, ...fetchOptions } = options;
    const accountPath = this.getAccountPath();
    const method = "POST";
    const url = `https://${accountPath}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql${
      query ? `?${querystring.stringify(query)}` : ""
    }`;
    const authorization = this.getAuthorizationHeader({ url, method });

    try {
      const res = await got(url, {
        method,
        json: { q: query },
        responseType: "json",
        headers: { Authorization: authorization, Prefer: "transient" },
        ...fetchOptions,
      });

      return res.body;
    } catch (err) {
      if (err.response) {
        console.log(err.response.body);
        return err.response.body;
      } else {
        throw err;
      }
    }
  }
}

module.exports = NetSuiteRest;
