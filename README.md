# QCBOM

Post quantum cryptographic bill of materials attestations on the Quantova network. QCBOM lets the party that runs a system prove the state and migration of its cryptographic assets without revealing the system. An inventory is opened, each cryptographic asset is recorded, its post quantum posture is assessed, remediation is recorded and the inventory is closed. Each record is signed with ML-DSA-65 under FIPS 204 and may be anchored to a Quantova time proof. Only a salted commitment ever leaves the party that holds the inventory.

## Install

```
npm install @quantovainc/qcbom
```

## Model

A QCBOM record is a signed envelope. The statement names an inventory by a random identifier and carries only the facts of a cryptographic asset and its migration. The five record types form a chain.

- open starts an inventory for a named system and scope
- asset records one cryptographic asset, its algorithm, usage and whether it is quantum vulnerable
- assess records the post quantum posture of a prior asset and the migration target
- remediate records the action taken on a prior asset
- close ends the inventory with a summary

asset refers back to the open of its inventory. assess, remediate and close refer to the record they follow. The chain lets any party replay the migration history of a system from its signed records.

## Use

```js
const Q = require('@quantovainc/qcbom')

const key = Q.generateKey()

const inventory = Q.open({
  key,
  system: 'api.gov.example',
  scope: 'all TLS endpoints of the public API',
  authorityLabel: 'Office of the CIO',
})

const asset = Q.asset({
  key,
  inventory,
  assetId: 'tls-api-01',
  assetType: 'certificate',
  algorithm: 'RSA-2048',
  usage: 'TLS for the public API',
  quantumVulnerable: true,
})

const result = await Q.verify(asset, { network: 'testnet', prior: inventory })
console.log(result.status)
```

## Verify

verify checks the ML-DSA-65 signature, that the signer is the authority the record names, the optional prior link, and any Quantova anchor. It returns a status of valid, unproven, indeterminate or invalid together with the individual checks. An anchor is accepted only when it was recorded under the QCBOM record kind on the network named in the options.

## Keys

A signing key is a 32 byte seed produced by generateKey. The seed stays with its holder and never appears in a record. A public key and a key identifier derived from it are what other parties use to verify.

## License

Apache-2.0 OR MIT. See LICENSE-APACHE and LICENSE-MIT.
