const ethUtil = require('ethereumjs-util');
const {
  recoverPersonalSignature,
  recoverTypedSignature,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');
const {
  TransactionFactory,
  Transaction: EthereumTx,
} = require('@ethereumjs/tx');
const SimpleKeyring = require('..');

const TYPE_STR = 'Whale Financial MPC';

// Sample account:
const testAccount = {
  key: '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952',
  address: '0x01560cd3bac62cc6d7e6380600d9317363400896',
};

const notKeyringAddress = '0xbD20F6F5F1616947a39E11926E78ec94817B3931';

describe('simple-keyring', function () {
  let keyring;
  beforeEach(function () {
    keyring = new SimpleKeyring();
  });

  describe('Keyring.type', function () {
    it('is a class property that returns the type string.', function () {
      const { type } = SimpleKeyring;
      expect(type).toBe(TYPE_STR);
    });
  });

  describe('#serialize empty wallets.', function () {
    it('serializes an empty array', async function () {
      const output = await keyring.serialize();
      expect(output).toHaveLength(0);
    });
  });

  describe('#deserialize a private key', function () {
    it('serializes what it deserializes', async function () {
      await keyring.deserialize([testAccount.key]);
      const serialized = await keyring.serialize();
      expect(serialized).toHaveLength(1);
      expect(serialized[0]).toBe(ethUtil.stripHexPrefix(testAccount.key));
    });
  });

  describe('#constructor with a private key', function () {
    it('has the correct addresses', async function () {
      const newKeyring = new SimpleKeyring([testAccount.key]);
      const accounts = await newKeyring.getAccounts();
      expect(accounts).toStrictEqual([testAccount.address]);
    });
  });

  describe('#signTransaction', function () {
    const address = '0x9858e7d8b79fc3e6d989636721584498926da38a';
    const privateKey =
      '0x7dd98753d7b4394095de7d176c58128e2ed6ee600abe97c9f6d9fd65015d9b18';
    const txParams = {
      from: address,
      nonce: '0x00',
      gasPrice: '0x09184e72a000',
      gasLimit: '0x2710',
      to: address,
      value: '0x1000',
    };

    it('returns a signed legacy tx object', async function () {
      await keyring.deserialize([privateKey]);
      const tx = new EthereumTx(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(address, tx);
      expect(signed.isSigned()).toBe(true);
    });

    it('returns a signed tx object', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(address, tx);
      expect(signed.isSigned()).toBe(true);
    });

    it('returns rejected promise if empty address is passed', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      await expect(keyring.signTransaction('', tx)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if wrong address is passed', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      await expect(
        keyring.signTransaction(notKeyringAddress, tx),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signMessage', function () {
    const address = '0x9858e7d8b79fc3e6d989636721584498926da38a';
    const message =
      '0x879a053d4800c6354e76c7985a865d2922c82fb5b3f4577b2fe08b998954f2e0';
    const privateKey =
      '0x7dd98753d7b4394095de7d176c58128e2ed6ee600abe97c9f6d9fd65015d9b18';
    const expectedResult =
      '0x28fcb6768e5110144a55b2e6ce9d1ea5a58103033632d272d2b5cf506906f7941a00b539383fd872109633d8c71c404e13dba87bc84166ee31b0e36061a69e161c';

    it('passes the dennis test', async function () {
      await keyring.deserialize([privateKey]);
      const result = await keyring.signMessage(address, message);
      expect(result).toBe(expectedResult);
    });

    it('reliably can decode messages it signs', async function () {
      await keyring.deserialize([privateKey]);
      const localMessage = 'hello there!';
      const msgHashHex = ethUtil.bufferToHex(
        ethUtil.keccak(Buffer.from(localMessage)),
      );

      await keyring.addAccounts(9);
      const addresses = await keyring.getAccounts();
      const signatures = await Promise.all(
        addresses.map(async (accountAddress) => {
          return await keyring.signMessage(accountAddress, msgHashHex);
        }),
      );
      signatures.forEach((sgn, index) => {
        const accountAddress = addresses[index];

        const r = ethUtil.toBuffer(sgn.slice(0, 66));
        const s = ethUtil.toBuffer(`0x${sgn.slice(66, 130)}`);
        const v = ethUtil.bufferToInt(
          ethUtil.toBuffer(`0x${sgn.slice(130, 132)}`),
        );
        const m = ethUtil.toBuffer(msgHashHex);
        const pub = ethUtil.ecrecover(m, v, r, s);
        const adr = `0x${ethUtil.pubToAddress(pub).toString('hex')}`;

        expect(adr).toBe(accountAddress);
      });
    });

    it('throw error for invalid message', async function () {
      await keyring.deserialize([privateKey]);
      await expect(keyring.signMessage(address, '')).rejects.toThrow(
        'Expected message to be an Uint8Array with length 32',
      );
    });

    it('throw error if empty address is passed', async function () {
      await keyring.deserialize([privateKey]);
      await expect(keyring.signMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if address not associated with the current keyring is passed', async function () {
      await keyring.deserialize([privateKey]);
      await expect(
        keyring.signMessage(notKeyringAddress, message),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#addAccounts', function () {
    describe('with no arguments', function () {
      it('creates a single wallet', async function () {
        await keyring.addAccounts();
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).toHaveLength(1);
      });
    });

    describe('with a numeric argument', function () {
      it('creates that number of wallets', async function () {
        await keyring.addAccounts(3);
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).toHaveLength(3);
      });
    });
  });

  describe('#getAccounts', function () {
    it('should return a list of addresses in wallet', async function () {
      // Push a mock wallet
      keyring.deserialize([testAccount.key]);

      const output = await keyring.getAccounts();
      expect(output).toHaveLength(1);
      expect(output[0]).toBe(testAccount.address);
    });
  });

  describe('#removeAccount', function () {
    describe('if the account exists', function () {
      it('should remove that account', async function () {
        await keyring.addAccounts();
        const addresses = await keyring.getAccounts();
        expect(addresses).toHaveLength(1);
        keyring.removeAccount(addresses[0]);
        const addressesAfterRemoval = await keyring.getAccounts();
        expect(addressesAfterRemoval).toHaveLength(0);
      });
    });

    describe('if the account does not exist', function () {
      it('should throw an error', function () {
        const unexistingAccount = '0x0000000000000000000000000000000000000000';
        expect(() => keyring.removeAccount(unexistingAccount)).toThrow(
          `Address ${unexistingAccount} not found in this keyring`,
        );
      });
    });
  });

  describe('#signPersonalMessage', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const privKeyHex = ethUtil.bufferToHex(privateKey);
    const message = '0x68656c6c6f20776f726c64';
    const expectedSignature =
      '0xce909e8ea6851bc36c007a0072d0524b07a3ff8d4e623aca4c71ca8e57250c4d0a3fc38fa8fbaaa81ead4b9f6bd03356b6f8bf18bccad167d78891636e1d69561b';

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signPersonalMessage(address, message);
      expect(signature).toBe(expectedSignature);

      const restored = recoverPersonalSignature({
        data: message,
        signature,
      });
      expect(restored).toBe(address);
    });

    it('throw error if empty address is passed', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(keyring.signPersonalMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if wrong address is passed', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.signPersonalMessage(notKeyringAddress, message),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signTypedData', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
    const expectedSignature =
      '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b';

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData);
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });

    it('returns the expected value if invalid version is given', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'FOO',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V1', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
    const expectedSignature =
      '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b';

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V1',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });

    it('works via version paramter', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData);
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V3', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '0x4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V3',
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V3 signature verification', function () {
    const privKeyHex =
      'c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4';
    const expectedSignature =
      '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' },
          ],
        },
        primaryType: 'Mail',
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        message: {
          from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello, Bob!',
        },
      };

      await keyring.deserialize([privKeyHex]);
      const addresses = await keyring.getAccounts();
      const [address] = addresses;
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V3',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V4', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '0x4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V4',
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V4,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#decryptMessage', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const privKeyHex = ethUtil.bufferToHex(privateKey);

    it('is not implemented', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(keyring.decryptMessage(address, {})).rejects.toThrow(
        "decryptMessage is not implemented in Whale Financial's WhaleKeyring.",
      );
    });
  });

  describe('#encryptionPublicKey', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const publicKey = 'GxuMqoE2oHsZzcQtv/WMNB3gCH2P6uzynuwO1P0MM1U=';
    const privKeyHex = ethUtil.bufferToHex(privateKey);

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const encryptionPublicKey = await keyring.getEncryptionPublicKey(
        address,
        privateKey,
      );
      expect(publicKey).toBe(encryptionPublicKey);
    });

    it('throw error if address is blank', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.getEncryptionPublicKey('', privateKey),
      ).rejects.toThrow('Must specify address.');
    });

    it('throw error if address is not present in the keyring', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.getEncryptionPublicKey(notKeyringAddress, privateKey),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signTypedData V4 signature verification', function () {
    const privKeyHex =
      'c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4';
    const expectedSignature =
      '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallets', type: 'address[]' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person[]' },
            { name: 'contents', type: 'string' },
          ],
          Group: [
            { name: 'name', type: 'string' },
            { name: 'members', type: 'Person[]' },
          ],
        },
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        primaryType: 'Mail',
        message: {
          from: {
            name: 'Cow',
            wallets: [
              '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
              '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
            ],
          },
          to: [
            {
              name: 'Bob',
              wallets: [
                '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
                '0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
                '0xB0B0b0b0b0b0B000000000000000000000000000',
              ],
            },
          ],
          contents: 'Hello, Bob!',
        },
      };

      await keyring.deserialize([privKeyHex]);

      const addresses = await keyring.getAccounts();
      const [address] = addresses;

      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V4',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V4,
      });
      expect(restored).toBe(address);
    });
  });

  describe('getAppKeyAddress', function () {
    it('should be unimplemented', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);
      await expect(
        simpleKeyring.getAppKeyAddress(address, 'someapp.origin.io'),
      ).rejects.toThrow(
        "getAppKeyAddress is not implemented in Whale Financial's WhaleKeyring.",
      );
    });
  });

  describe('exportAccount', function () {
    it('should be unimplemented', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);
      await expect(simpleKeyring.exportAccount(address)).rejects.toThrow(
        "exportAccount is not implemented in Whale Financial's WhaleKeyring.",
      );
    });
  });
});
