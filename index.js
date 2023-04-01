const { randomBytes } = require('crypto');
const { EventEmitter } = require('events');
const ethUtil = require('ethereumjs-util');
const {
  concatSig,
  SignTypedDataVersion
} = require('@metamask/eth-sig-util');
const { TransactionFactory } = require('@ethereumjs/tx');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { bytesToHex } = require('ethereum-cryptography/utils');

const {
  gql,
  ApolloClient,
  createHttpLink,
  InMemoryCache,
  split,
} = require('@apollo/client/core');
const { GraphQLWsLink } = require('@apollo/client/link/subscriptions');
const { getMainDefinition } = require('@apollo/client/utilities');
const { createClient } = require('graphql-ws');
const { setContext } = require('@apollo/client/link/context');
const uuidv4 = require('uuid').v4;
const fetch = require('cross-fetch');

const type = 'Waymont Co. SCW';

const CREATE_CROSS_CHAINS_WALLET = gql`
  mutation CreateCrossChainsWallet($data: CreateCrossChainsWalletInput!) {
    createCrossChainsWallet(data: $data) {
      ... on Wallet {
        id
        name
        address
        currency
      }
      ... on ErrorResponse {
        message
      }
    }
  }
`;

const LIST_WALLETS = gql`
  query ListWallets {
    wallets {
      id
      name
      currency
      blockchain
      address
    }
  }
`;

const CREATE_WALLET_SIGNING_REQUEST = gql`
  mutation CreateWalletSigningRequest($data: CreateWalletSigningRequestInput!) {
    createWalletSigningRequest(data: $data) {
      ... on MfaSession {
        id
      }

      ... on ErrorResponse {
        message
      }
    }
  }
`;

const SIGN_MESSAGE = gql`
  mutation SignMessage($data: SignMessageInput!) {
    signMessage(data: $data) {
      ... on Signature {
        fullSig
        r
        s
        v
      }

      ... on ErrorResponse {
        message
      }
    }
  }
`;

const SIGN_TYPED_DATA = gql`
  mutation SignTypedData($data: SignTypedDataInput!) {
    signTypedData(data: $data) {
      ... on Signature {
        fullSig
        r
        s
        v
      }

      ... on ErrorResponse {
        message
      }
    }
  }
`;

const UPDATE_WALLET = gql`
  mutation UpdateWallet($where: WalletWhereUniqueInput!, $data: UpdateOneWalletInput!) {
    updateWallet(where: $where, data: $data) {
      ... on Wallet {
        name
      }
    }
  }
`;

const CORE_WALLET_TRANSACTION_FRAGMENT = gql`
  fragment CoreWalletTransaction on Transaction {
    id
    txHash
    chainId
    relayedForWallet
    walletTransactionTo
    assetRecipient
    to
    from
    data
    asset {
      name
      address
      decimals
      symbol
      type
    }
    amount
    createdAt
    updatedAt
  }
`;

const CORE_MFA_SESSION_FRAGMENT = gql`
  fragment CoreMFASession on MfaSession {
    id
    isAuthenticatorVerified
    isEmailOneTimeCodeVerified
    actionsToExecute
    challengeString
    mfaOptions
    status
    wallet {
      id
      name
      address
    }
    executionTimelockInSeconds
    executionAllowedAtTimestamp
    createdAtTimestamp
    expiresIn
    transaction {
      ...CoreWalletTransaction
    }
    authUserId
    authUser {
      id
      email
    }
    initiatedBy {
      displayName
    }
  }
  ${CORE_WALLET_TRANSACTION_FRAGMENT}
`;

const CHECK_AUTH_STATUS = gql`
  query CheckAuthStatus {
    checkAuthStatus {
      ... on MfaSession {
        ...CoreMFASession
      }
      ... on ErrorResponse {
        errorMessage: message
      }
      ... on SuccessResponse {
        successMessage: message
      }
    }
  }
  ${CORE_MFA_SESSION_FRAGMENT}
`;

const MFA_RESOLVERS = {};
const MFA_SETUP_WINDOW_DATA = {};

class WhaleKeyring extends EventEmitter {
  constructor(accessToken, baseAppUrl, baseAPIUrl, setLocked) {
    super();
    this.type = type;
    this.deserialize(accessToken);

    this.baseAppUrl = baseAppUrl;
    this.setLocked = setLocked;

    const httpLink = createHttpLink({
      uri: `${baseAPIUrl}/graphql`,
      credentials: 'include',
      fetch
    });
    
    const [apiProtocol, apiPathname] = baseAPIUrl.split('://');

    const wsProtocol = apiProtocol === 'https' ? 'wss' : 'ws';

    // @todo add authentication over WebSocket
    const wsLink = new GraphQLWsLink(
      createClient({
        url: `${wsProtocol}://${apiPathname}/graphql`,
        webSocketImpl: WebSocket
      }),
    );

    const authLink = setContext(async (_, { headers }) => {
      if (headers === undefined) headers = {};
      headers.authorization = `Bearer ${this.accessToken}`;
      return { headers };
    });

    // The split function takes three parameters:
    //
    // * A function that's called for each operation to execute
    // * The Link to use for an operation if the function returns a "truthy" value
    // * The Link to use for an operation if the function returns a "falsy" value
    const splitLink = split(
      ({ query }) => {
        const definition = getMainDefinition(query);
        return (
          definition.kind === 'OperationDefinition' &&
          definition.operation === 'subscription'
        );
      },
      wsLink,
      httpLink,
    );

    this.apolloClient = new ApolloClient({
      cache: new InMemoryCache(),
      link: authLink.concat(splitLink),
    });
  }

  async checkMfaStatus(noCache) {
    const res = await this.apolloClient.query({
      query: CHECK_AUTH_STATUS,
      fetchPolicy: noCache ? "no-cache" : undefined
    });
    return !(res.data.checkAuthStatus.successMessage !== undefined && res.data.checkAuthStatus.successMessage === "No MFA options found");
  }

  // Not really serializing anything but we'll call it this to keep things similar to MM
  async serialize() {
    return this.accessToken;
  }

  // Not really deserializing anything but we'll call it this to keep things similar to MM
  async deserialize(accessToken) {
    this.accessToken = accessToken;
  }

  async addAccounts(n = 1, names) {
    const prevAccountCount = (await this.getAccounts()).length;
    const newWallets = [];
    for (let i = 0; i < n; i++) {
      const res = await this.apolloClient.mutate({
        mutation: CREATE_CROSS_CHAINS_WALLET,
        variables: {
          data: {
            walletName: names !== undefined ? names[i] : `Account ${
              prevAccountCount + 1 + i
            } from ${new Date().toDateString()}`,
          },
        },
      });

      if (res.data?.createCrossChainsWallet.__typename === "ErrorResponse") throw "Error creating wallet: " + res.data.createCrossChainsWallet.message;
      newWallets.push(res.data.createCrossChainsWallet.address);
    }
    this.newAccountsCache = this.newAccountsCache !== undefined ? this.newAccountsCache.concat(newWallets) : newWallets;
    return newWallets;
  }

  async renameAccount(address, name) {
    await this.apolloClient.mutate({
      mutation: UPDATE_WALLET,
      variables: {
        where: {
          address
        },
        data: {
          name: { set: name }
        }
      },
    });
  }

  async getAccounts() {
    const res = await this.apolloClient.query({
      query: LIST_WALLETS,
    });
    var wallets = res.data.wallets.map(({ address }) => address);
    return this.newAccountsCache !== undefined ? wallets.concat(this.newAccountsCache.filter((item) => wallets.indexOf(item) < 0)) : wallets;
  }

  async getAccountNames() {
    const res = await this.apolloClient.query({
      query: LIST_WALLETS,
    });
    var names = {};
    for (const wallet of res.data.wallets) names[wallet.address.toLowerCase()] = wallet.name;
    return names;
  }

  formatUnits(input, decimals) {
    input = input.toString();
    return input.length > decimals ?
      input.substring(0, input.length - decimals) + "." + input.substring(input.length - decimals) :
      "0." + "0".repeat(decimals - input.length) + input;
  }

  async sendTransaction(address, tx) {
    var json = tx.toJSON();
    var res = await this.apolloClient.mutate({
      mutation: CREATE_WALLET_SIGNING_REQUEST,
      variables: {
        data: {
          type: tx.type, // no longer used--all Waymont TXs are now EIP-1559
          data: json.data !== "0x" ? json.data : undefined,
          chainId: parseInt(tx.type > 0 ? tx.chainId.toString() : tx.common._chainParams.chainId.toString()),
          from: address,
          to: json.to,
          maxFeePerGas: json.maxFeePerGas,
          maxPriorityFeePerGas: json.maxPriorityFeePerGas,
          gasLimit: ((parseInt(json.gasLimit.toString()) * 2) + 100000).toString(), // TODO: Calculate gas limit accurately using Wallet.simulateFunctionCall
          value: tx.value.toString(),
          // nonce: tx.nonce.toNumber(), // TODO: Nonces
          gasPrice: json.gasPrice,
          accessList: json.accessList
        },
      },
    });

    if (res.data.createWalletSigningRequest.__typename === "MfaSession") {
      res.data.createWalletSigningRequest = await new Promise((resolve, reject) => {
        // if (MFA_RESOLVERS[address.toLowerCase()] === undefined) MFA_RESOLVERS[address.toLowerCase()] = {}; // TODO: Nonces
        MFA_RESOLVERS[address.toLowerCase()]/* [tx.nonce.toString()] */ = { resolve, reject }; // TODO: Nonces
        chrome.windows.create({
          url: this.baseAppUrl + '/mfa/' + res.data.createWalletSigningRequest.id,
          focused: true,
          type: 'popup',
          width: 600,
          height: 700,
        }, function (mfaWindow) {
          chrome.windows.onRemoved.addListener(function (removedWindowIndex) {
            if (removedWindowIndex === mfaWindow.id && MFA_RESOLVERS[address.toLowerCase()] !== undefined) {
              reject("Waymont MFA window closed");
            }
          });
        });
      });
    } else if (res.data.createWalletSigningRequest.transactionHash === undefined) {
      if (res.data.createWalletSigningRequest.__typename === "ErrorResponse") {
        if (res.data.createWalletSigningRequest.message === "Unauthorized") {
          this.setLocked(true);
          throw new Error("Logged out...");
        }
        throw new Error(res.data.createWalletSigningRequest.message);
      }
      throw new Error("Unknown Waymont API error when signing transaction");
    }

    return res.data.createWalletSigningRequest.transactionHash;
  }

  mfaResolution(transactionData, errorMessage) {
    let resolver = MFA_RESOLVERS[transactionData.from.toLowerCase()]/* [transactionData.nonce.toString()] */; // TODO: Nonces
    if (transactionData.transactionHash) resolver.resolve(transactionData);
    else if (errorMessage !== undefined && typeof errorMessage === 'string' && errorMessage.length > 0) resolver.reject(new Error(errorMessage));
    else resolver.reject(new Error("Unknown error during Waymont MFA resolution."));
    MFA_RESOLVERS[transactionData.from.toLowerCase()] = undefined; // TODO: Nonces
  }

  // For eth_sign, we need to sign arbitrary data:
  async signMessage(address, data, _opts = {}) {
    // Not supported because of potential transaction policies
    // Also, the smart contract wallet does not support isValidSignature yet
    throw "eth_sign is not supported by Waymont Co.'s WhaleKeyring.";
  }

  // For personal_sign, we need to prefix the message:
  async signPersonalMessage(address, msgHex, _opts = {}, processTransaction, origin) {
    // Check origin
    let hostname = (new URL(origin)).hostname;
    let parts = hostname.split(".");
    let rootDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
    if (rootDomain !== "opensea.io" && !confirm("This dApp is trying to sign a message, but Waymont is unsure if the dApp supports Waymont wallets (which use EIP-1271 smart contract signatures). Do you want to try anyway (might be a waste of gas)?")) throw "Attemped EIP-1271 message signing canceled by user.";

    // Prefix and hash message
    if (msgHex.length >= 2 && msgHex.substring(0, 2) === "0x") msgHex = msgHex.substring(2);
    const message = Buffer.from(msgHex, 'hex');
    const prefix = Buffer.from(
      `\u0019Ethereum Signed Message:\n${message.length.toString()}`,
      'utf-8'
    )
    let hashHex = bytesToHex(keccak256(Buffer.concat([prefix, message])));
    if (hashHex.substring(0, 2) === "0x") hashHex = hashHex.substring(2);
    
    // Generate random fake/dummy signature (mimic a real signature--65 bytes; `s` should be <= `0x7f...`)
    let r = randomBytes(32);
    let s = randomBytes(32);
    let count = 0;
    while (Buffer.compare(s, Buffer.from("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", "hex")) === 1) {
      s = randomBytes(32);
      count++;
      if (count >= 1000) throw "Failed to generate random number";
    }
    let signature = Buffer.concat([r, s, Buffer.from("1c", "hex")]);
    let signatureHashHex = bytesToHex(keccak256(signature));
    if (signatureHashHex.substring(0, 2) === "0x") signatureHashHex = signatureHashHex.substring(2); // REMOVE 0x

    // Send setValidSignedMessageHash TX
    let tx = {
      from: address.toLowerCase(),
      to: address,
      data: "0x5e9e88cd" + hashHex + signatureHashHex + "0000000000000000000000000000000000000000000000000000000000000001",
    };
    await processTransaction(tx, {
      method: 'eth_sendTransaction',
      params: [tx],
      origin
    });

    // Wait 15 seconds for the TX confirmation to propagate
    chrome.windows.create({
      url: 'data:text/html,<head><title>Please wait 15 seconds...</title></head><body style="display: flex; align-items: center; justify-content: center; text-align: center; padding: 20px 25px; font-family: monospace;"><h1 style="margin: 0;">Please wait 15 seconds while your transaction propagates... (This window will close automatically.)</h1><script>setTimeout(window.close, 15000);</script>',
      focused: true,
      type: 'popup',
      width: 600,
      height: 200,
    });
    await new Promise((resolve) => setTimeout(resolve, 15000));

    // Return dummy signature (65 bytes; `s` should be <= `0x7f...`)
    let signatureHex = signature.toString("hex");
    if (signatureHex.substring(0, 2) !== "0x") signatureHex = "0x" + signatureHex; // ADD 0x
    return signatureHex;
  }

  // For eth_decryptMessage:
  async decryptMessage(_withAccount, _encryptedData) {
    throw new Error(
      "decryptMessage is not implemented in Waymont Co.'s WhaleKeyring.",
    );
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(
    withAccount,
    typedData,
    opts = { version: SignTypedDataVersion.V1 },
  ) {
    // Not supported for now (the smart contract wallet does not support isValidSignature yet)
    throw new Error(
      "signTypedData is not implemented in Waymont Co.'s WhaleKeyring.",
    );
    
    // Treat invalid versions as "V1"
    const version = Object.keys(SignTypedDataVersion).includes(opts.version)
      ? opts.version
      : SignTypedDataVersion.V1;

    return this._signTypedData({
      address: withAccount,
      data: typedData,
      version,
    });
  }

  /**
   * Sign typed data according to EIP-712. The signing differs based upon the `version`.
   *
   * V1 is based upon [an early version of EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
   * that lacked some later security improvements, and should generally be neglected in favor of
   * later versions.
   *
   * V3 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), except that arrays and
   * recursive data structures are not supported.
   *
   * V4 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), and includes full support of
   * arrays and recursive data structures.
   *
   * @param options - The signing options.
   * @param options.privateKey - The private key to sign with.
   * @param options.data - The typed data to sign.
   * @param options.version - The signing version to use.
   * @returns The '0x'-prefixed hex encoded signature.
   */
  async _signTypedData({ address, data, version }) {
    this.validateVersion(version);
    if (this.isNullish(data)) {
      throw new Error('Missing data parameter');
    } else if (this.isNullish(address)) {
      throw new Error('Missing private key parameter');
    }

    var res = await this.apolloClient.mutate({
      mutation: SIGN_TYPED_DATA,
      variables: {
        data: {
          walletAddress: address,
          content: data,
          version
        },
      },
    });
    if (res.data.signTypedData.r === undefined) {
      if (res.data.signTypedData.__typename === "ErrorResponse") throw new Error(res.data.signTypedData.message);
      throw new Error("Unknown Waymont API error when signing typed data");
    }
    return concatSig(ethUtil.toBuffer(res.data.signTypedData.v), res.data.signTypedData.r, res.data.signTypedData.s);
  }

  /**
   * Validate that the given value is a valid version string.
   *
   * @param version - The version value to validate.
   * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
   * allowed.
   */
  validateVersion(
    version,
    allowedVersions
  ) {
    if (!Object.keys(SignTypedDataVersion).includes(version)) {
      throw new Error(`Invalid version: '${version}'`);
    } else if (allowedVersions && !allowedVersions.includes(version)) {
      throw new Error(
        `SignTypedDataVersion not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(
          ', ',
        )}`,
      );
    }
  }

  /**
   * Returns `true` if the given value is nullish.
   *
   * @param value - The value being checked.
   * @returns Whether the value is nullish.
   */
  isNullish(value) {
    return value === null || value === undefined;
  }

  // get public key for nacl
  async getEncryptionPublicKey(_withAccount, _opts = {}) {
    throw new Error(
      "getEncryptionPublicKey is not implemented in Waymont Co.'s WhaleKeyring.",
    );
  }

  // returns an address specific to an app
  async getAppKeyAddress(_address, _origin) {
    throw new Error(
      "getAppKeyAddress is not implemented in Waymont Co.'s WhaleKeyring.",
    );
  }

  // exportAccount should return a hex-encoded private key:
  async exportAccount(address, opts = {}) {
    throw new Error(
      "exportAccount is not implemented in Waymont Co.'s WhaleKeyring.",
    );
  }

  logout() {
    return chrome.windows.create({
      url: this.baseAppUrl + '/logout/',
      focused: false,
      type: 'popup',
      width: 400,
      height: 300,
    });
  }

  async waitForMfaSetup() {
    if (!this.forceNextMfaSetup) throw "No interaction from user, not logging in (this is not an error, just a warning)";
    this.forceNextMfaSetup = false;
    if (MFA_SETUP_WINDOW_DATA.id !== undefined) {
      chrome.windows.update(MFA_SETUP_WINDOW_DATA.id, { focused: true });
      throw "MFA setup window already open";
    }
    const checkMfaStatus = this.checkMfaStatus.bind(this);
    await new Promise((resolve, reject) => {
      chrome.windows.create({
        url: this.baseAppUrl + '/mfa/setup/',
        focused: true,
        type: 'popup',
        width: 600,
        height: 700,
      }, function (mfaSetupWindow) {
        MFA_SETUP_WINDOW_DATA.id = mfaSetupWindow.id;
        chrome.windows.onRemoved.addListener(async function (removedWindowIndex) {
          if (MFA_SETUP_WINDOW_DATA.id !== undefined && removedWindowIndex === mfaSetupWindow.id) {
            MFA_SETUP_WINDOW_DATA.id = undefined;
            if (!(await checkMfaStatus(true))) reject("MFA setup window closed")
            resolve();
          }
        });
        let lastFocusedWindowId = mfaSetupWindow.id;
        chrome.windows.onFocusChanged.addListener(async function (focusedWindowIndex) {
          let _lastFocusedWindowId = lastFocusedWindowId;
          lastFocusedWindowId = focusedWindowIndex;
          if (_lastFocusedWindowId === mfaSetupWindow.id && focusedWindowIndex !== mfaSetupWindow.id && await checkMfaStatus(true)) {
            MFA_SETUP_WINDOW_DATA.id = undefined;
            chrome.windows.remove(mfaSetupWindow.id);
            resolve();
          }
        });
      });
    });
  }
}

WhaleKeyring.type = type;
module.exports = WhaleKeyring;
