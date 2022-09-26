const { EventEmitter } = require('events');
const ethUtil = require('ethereumjs-util');
const {
  concatSig,
  SignTypedDataVersion,
  typedSignatureHash,
  TypedDataUtils,
} = require('@metamask/eth-sig-util');
const { TransactionFactory } = require('@ethereumjs/tx');

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

const type = 'Kevlar Co. MPC';
const baseAPIUrl = 'https://api-staging.kevlarco.com';

const httpLink = createHttpLink({
  uri: `${baseAPIUrl}/graphql`,
  credentials: 'include',
  fetch
});

const [apiProtocol, apiPathname] = baseAPIUrl.split('://');

const CREATE_WALLET = gql`
  mutation CreateWallet($data: CreateOneWalletInput!) {
    createWallet(data: $data) {
      id
      name
      address
      currency
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
      keyQuorum {
        address
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
        publicKey
      }

      ... on ErrorResponse {
        message
      }
    }
  }
`;

class WhaleKeyring extends EventEmitter {
  constructor(accessToken) {
    super();
    this.type = type;
    this.deserialize(accessToken);

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
        mutation: CREATE_WALLET,
        variables: {
          data: {
            sessionId: uuidv4(),
            name: names !== undefined ? names[i] : `Account ${
              prevAccountCount + 1 + i
            } from ${new Date().toDateString()}`,
            parties: 3,
            threshold: 2,
            blockchain: 'ETHEREUM',
            currency: 'USD',
          },
        },
      });

      newWallets.push(res.data.createWallet.address);
    }
    this.newAccountsCache = this.newAccountsCache !== undefined ? this.newAccountsCache.concat(newWallets) : newWallets;
    return newWallets;
  }

  async getAccounts() {
    const res = await this.apolloClient.query({
      query: LIST_WALLETS,
    });
    var wallets = res.data.wallets.map(({ address }) => address);
    return this.newAccountsCache !== undefined ? wallets.concat(this.newAccountsCache.filter((item) => wallets.indexOf(item) < 0)) : wallets;
  }

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction(address, tx) {
    let rawTxHex;
    // transactions built with older versions of ethereumjs-tx have a
    // getChainId method that newer versions do not. Older versions are mutable
    // while newer versions default to being immutable. Expected shape and type
    // of data for v, r and s differ (Buffer (old) vs BN (new))
    if (typeof tx.getChainId === 'function') {
      // In this version of ethereumjs-tx we must add the chainId in hex format
      // to the initial v value. The chainId must be included in the serialized
      // transaction which is only communicated to ethereumjs-tx in this
      // value. In newer versions the chainId is communicated via the 'Common'
      // object.
      tx.v = ethUtil.bufferToHex(tx.getChainId());
      tx.r = '0x00';
      tx.s = '0x00';

      rawTxHex = tx.serialize().toString('hex');

      return this._signTransaction(address, rawTxHex, (payload) => {
        tx.v = Buffer.from(payload.v, 'hex');
        tx.r = Buffer.from(payload.r, 'hex');
        tx.s = Buffer.from(payload.s, 'hex');
        return tx;
      });
    }

    // The below `encode` call is only necessary for legacy transactions, as `getMessageToSign`
    // calls `rlp.encode` internally for non-legacy transactions. As per the "Transaction Execution"
    // section of the ethereum yellow paper, transactions need to be "well-formed RLP, with no additional
    // trailing bytes".

    // Note also that `getMessageToSign` will return valid RLP for all transaction types, whereas the
    // `serialize` method will not for any transaction type except legacy. This is because `serialize` includes
    // empty r, s and v values in the encoded rlp. This is why we use `getMessageToSign` here instead of `serialize`.
    const messageToSign = tx.getMessageToSign(false);

    rawTxHex = Buffer.isBuffer(messageToSign)
      ? messageToSign.toString('hex')
      : ethUtil.rlp.encode(messageToSign).toString('hex');

    return this._signTransaction(address, rawTxHex, (payload) => {
      // Because tx will be immutable, first get a plain javascript object that
      // represents the transaction. Using txData here as it aligns with the
      // nomenclature of ethereumjs/tx.
      const txData = tx.toJSON();
      // The fromTxData utility expects a type to support transactions with a type other than 0
      txData.type = tx.type;
      // The fromTxData utility expects v,r and s to be hex prefixed
      txData.v = ethUtil.addHexPrefix(payload.v);
      txData.r = ethUtil.addHexPrefix(payload.r);
      txData.s = ethUtil.addHexPrefix(payload.s);
      // Adopt the 'common' option from the original transaction and set the
      // returned object to be frozen if the original is frozen.
      return TransactionFactory.fromTxData(txData, {
        common: tx.common,
        freeze: Object.isFrozen(tx),
      });
    });
  }

  _signTransaction(address, rawTxHex, handleSigning) {
    return new Promise((resolve, reject) => {
      this._signData(address, rawTxHex).then(function (payload) {
        const newOrMutatedTx = handleSigning(payload);
        const valid = newOrMutatedTx.verifySignature();
        if (valid) {
          resolve(newOrMutatedTx);
        } else {
          reject(
            new Error(
              'Kevlar Co. MPC: The transaction signature is not valid',
            ),
          );
        }
      });
    });
  }

  _signData(address, message) {
    return this.apolloClient.mutate({
      mutation: SIGN_MESSAGE,
      variables: {
        data: {
          walletAddress: address,
          content: message
        },
      },
    });
  }

  // For eth_sign, we need to sign arbitrary data:
  async signMessage(address, data, _opts = {}) {
    const msgSig = await this._signData(address, data);
    const rawMsgSig = concatSig(msgSig.v, msgSig.r, msgSig.s);
    return rawMsgSig;
  }

  // For personal_sign, we need to prefix the message:
  async signPersonalMessage(address, msgHex, _opts = {}) {
    const msgHashHex = ethUtil.bufferToHex(
      ethUtil.hashPersonalMessage(Buffer.from(msgHex, 'hex')),
    );
    const msgSig = await this._signData(address, msgHashHex);
    const rawMsgSig = concatSig(msgSig.v, msgSig.r, msgSig.s);
    return rawMsgSig;
  }

  // For eth_decryptMessage:
  async decryptMessage(_withAccount, _encryptedData) {
    throw new Error(
      "decryptMessage is not implemented in Kevlar Co.'s WhaleKeyring.",
    );
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(
    withAccount,
    typedData,
    opts = { version: SignTypedDataVersion.V1 },
  ) {
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

    const messageHash =
      version === SignTypedDataVersion.V1
        ? Buffer.from(typedSignatureHash(data), 'hex')
        : TypedDataUtils.eip712Hash(data, version);
    const sig = await this._signData(address, messageHash);
    return concatSig(ethUtil.toBuffer(sig.v), sig.r, sig.s);
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
      "getEncryptionPublicKey is not implemented in Kevlar Co.'s WhaleKeyring.",
    );
  }

  // returns an address specific to an app
  async getAppKeyAddress(_address, _origin) {
    throw new Error(
      "getAppKeyAddress is not implemented in Kevlar Co.'s WhaleKeyring.",
    );
  }

  // exportAccount should return a hex-encoded private key:
  async exportAccount(address, opts = {}) {
    throw new Error(
      "exportAccount is not implemented in Kevlar Co.'s WhaleKeyring.",
    );
  }
}

WhaleKeyring.type = type;
module.exports = WhaleKeyring;
