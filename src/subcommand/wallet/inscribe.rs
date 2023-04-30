use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, SchnorrSighashType, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};

#[derive(Serialize)]
struct Output {
  commit: Txid,
  inscription: InscriptionId,
  reveal: Txid,
  fees: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(long, help = "Use fee rate of <FEE_RATE> sats/vB")]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> sats/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe sat with contents of <FILE>")]
  pub(crate) file: PathBuf,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(long, help = "Use voodoo powers to inscribe under moonlight.")]
  pub(crate) nocturnal: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address>,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let inscription = Inscription::from_file(options.chain(), &self.file)?;

    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];

    // TODO: cursed may not be able to be sent out to destination

    /*
     Overview

    1. Gather wallet UTXOs
    2. create dummy reveal tx
    3. calculate fee requirement for dummy reveal
    4. utx_commit
    - output[0]: itxo_commit, 10K + reveal_fee
    - output[1]: voodoo, 10K
    - output[2]: change
    - fee: commit_fee
    3. utx_reveal
    - input[0]: voodoo, 10K
    - input[1]: <(itxo_commit, 10K + reveal_fee)
    - output[0]: voodoo_change 10K
    - output[1]: itxo_genesis, 10K
    - fee: reveal_fee
    4. sign(utx_commit), sign(utx_reveal)
    5. dry-run / broadcast

    */

    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    let (unsigned_commit_tx, reveal_tx, recovery_key_pair) =
      Inscribe::create_inscription_transactions(
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        reveal_tx_destination,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
        self.nocturnal,
      )?;

    if self.nocturnal {
      utxos.insert(
        reveal_tx.input[0].previous_output,
        TransactionBuilder::TARGET_POSTAGE,
      );

      utxos.insert(
        reveal_tx.input[1].previous_output,
        Amount::from_sat(
          unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
        ),
      );
      {
        //let utxos_after = utxos.clone();
        //dbg!(utxos_after);
      }
    } else {
      utxos.insert(
        reveal_tx.input[0].previous_output,
        Amount::from_sat(
          unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
        ),
      );
    }

    let fees_commit = Self::calculate_fee(&unsigned_commit_tx, &utxos);
    let fees_reveal = Self::calculate_fee(&reveal_tx, &utxos);
    let _fees = fees_commit + fees_reveal;
    let fees = 0;

    if self.dry_run {
      print_json(Output {
        commit: unsigned_commit_tx.txid(),
        reveal: reveal_tx.txid(),
        inscription: reveal_tx.txid().into(),
        fees,
      })?;

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let unsigned_commit_tx_inputs: Vec<(usize, OutPoint, Amount)> = unsigned_commit_tx
        .clone()
        .input
        .iter()
        .enumerate()
        .map(|(n, i)| {
          (
            n,
            i.previous_output,
            utxos.get(&i.previous_output).unwrap().clone(),
          )
        })
        .collect();

      let reveal_tx_inputs: Vec<(usize, OutPoint, Amount)> = reveal_tx
        .clone()
        .input
        .iter()
        .enumerate()
        .map(|(n, i)| {
          (
            n,
            i.previous_output,
            utxos.get(&i.previous_output).unwrap().clone(),
          )
        })
        .collect();

      dbg!("FINALIZE");

      dbg!(
        &unsigned_commit_tx.txid(),
        &unsigned_commit_tx.output,
        &unsigned_commit_tx_inputs,
      );

      dbg!(&reveal_tx.txid(), &reveal_tx.output, &reveal_tx_inputs,);

      let reveal_raw_tx = bitcoin::consensus::serialize(&reveal_tx);

      let test_mempool_accept = client.test_mempool_accept(&[&signed_raw_commit_tx])?;
      dbg!(&test_mempool_accept);
      let test_mempool_accept =
        client.test_mempool_accept(&[&signed_raw_commit_tx, &reveal_raw_tx])?;
      dbg!(&test_mempool_accept);

      //dbg!(&unsigned_commit_tx);
      //dbg!(&reveal_tx);
    } else {
      if !self.no_backup {
        Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

      let reveal = client
        .send_raw_transaction(&reveal_tx)
        .context("Failed to send reveal transaction")?;

      print_json(Output {
        commit,
        reveal,
        inscription: reveal.into(),
        fees,
      })?;
    };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tx.input
      .iter()
      .map(|txin| {
        let prev = &txin.previous_output;
        let value = utxos
          .get(prev)
          .expect("All spent inputs should be found in the internal utxo set");
        //dbg!(txin.previous_output, value);
        value.to_sat()
        // utxos
        //   .get(&txin.previous_output)c
        //   .expect("All spent inputs should be found in the internal utxo set")
        //   .to_sat()
      })
      .sum::<u64>()
      .checked_sub(
        tx.output
          .iter()
          .map(|txout| {
            //dbg!(txout.value);

            txout.value
          })
          .sum::<u64>(),
      )
      .expect("Transaction input value is less than output value")
  }

  fn create_inscription_transactions(
    satpoint: Option<SatPoint>,
    inscription: Inscription,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    network: Network,
    utxos: BTreeMap<OutPoint, Amount>,
    change: [Address; 2],
    destination: Address,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
    nocturnal: bool,
  ) -> Result<(Transaction, Transaction, TweakedKeyPair)> {
    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        return Err(anyhow!("sat at {} already inscribed", satpoint));
      }

      if inscribed_satpoint.outpoint == satpoint.outpoint {
        return Err(anyhow!(
          "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
          satpoint.outpoint,
        ));
      }
    }

    let secp256k1 = Secp256k1::new();
    use rand::SeedableRng;
    let seed = [1u8; 32];
    let mut seeded_rng = secp256k1::rand::rngs::StdRng::from_seed(seed);
    let key_pair = UntweakedKeyPair::new(&secp256k1, &mut seeded_rng);

    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let virgin_keypair = key_pair.tap_tweak(&secp256k1, None);
    let (_virgin_public, _parity) = XOnlyPublicKey::from_keypair(&virgin_keypair.to_inner());

    let reveal_script = inscription.append_reveal_script(
      script::Builder::new()
        .push_slice(&public_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG),
    );

    let taproot_spend_info = TaprootBuilder::new()
      .add_leaf(0, reveal_script.clone())
      .expect("adding leaf should work")
      .finalize(&secp256k1, public_key)
      .expect("finalizing taproot builder should work");

    let control_block = taproot_spend_info
      .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
      .expect("should compute control block");

    let voodoo_address = Address::p2tr(&secp256k1, public_key, None, network);
    let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);
    let (virgin_xopk, _parity) = virgin_keypair.to_inner().x_only_public_key();

    let virgin_address = Address::p2tr_tweaked(
      TweakedPublicKey::dangerous_assume_tweaked(virgin_xopk),
      network,
    );
    dbg!(assert_eq!(voodoo_address, virgin_address));
    dbg!(&voodoo_address);
    dbg!(&virgin_address);
    dbg!(&commit_tx_address);

    let voodoo_change_address = change[1].clone();

    let (_, reveal_fee) = if nocturnal {
      Self::build_nocturnal_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint::null(),
        OutPoint::null(),
        TxOut {
          script_pubkey: voodoo_change_address.clone().script_pubkey(),
          value: 0,
        },
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: 0,
        },
        &reveal_script,
      )
    } else {
      Self::build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint::null(),
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: 0,
        },
        &reveal_script,
      )
    };

    let commit_fee_rate = if !nocturnal {
      commit_fee_rate
    } else {
      FeeRate::try_from(10.).unwrap()
    };

    let output_value = if nocturnal {
      // larger than needed to cover the
      reveal_fee + TransactionBuilder::TARGET_POSTAGE + TransactionBuilder::TARGET_POSTAGE
    } else {
      reveal_fee + TransactionBuilder::TARGET_POSTAGE
    };

    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
      satpoint,
      inscriptions,
      utxos,
      commit_tx_address.clone(),
      change,
      commit_fee_rate,
      output_value,
    )?;

    let (unsigned_commit_tx, reveal_tx) = if !nocturnal {
      let (vout, output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
        .expect("should find sat commit/inscription output");

      let (mut reveal_tx, fee) = Self::build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint {
          txid: unsigned_commit_tx.txid(),
          vout: vout.try_into().unwrap(),
        },
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: output.value,
        },
        &reveal_script,
      );

      reveal_tx.output[0].value = reveal_tx.output[0]
        .value
        .checked_sub(fee.to_sat())
        .context("commit transaction output value insufficient to pay transaction fee")?;

      if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
        bail!("commit transaction output would be dust");
      }

      let mut sighash_cache = SighashCache::new(&mut reveal_tx);
      let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
          0,
          &Prevouts::All(&[output]),
          TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
          SchnorrSighashType::Default,
        )
        .expect("signature hash should compute");

      let signature = secp256k1.sign_schnorr(&signature_hash.into(), &key_pair);

      let witness = sighash_cache
        .witness_mut(0)
        .expect("getting mutable witness reference should work");
      witness.push(signature.as_ref());
      witness.push(reveal_script);
      witness.push(&control_block.serialize());

      (unsigned_commit_tx, reveal_tx)
    } else {
      //let fee = Amount::from_sat(2000);
      let mut unsigned_commit_tx = unsigned_commit_tx;
      // region: --- vodoo spell

      // we add another output at the end of the transaction to pay for the voodoo
      unsigned_commit_tx.output.push(TxOut {
        value: TransactionBuilder::TARGET_POSTAGE.to_sat(),
        script_pubkey: voodoo_address.script_pubkey(),
      });

      let unsigned_commit_tx = unsigned_commit_tx;
      let (voodo_vout, voodoo_output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| output.script_pubkey == voodoo_address.script_pubkey())
        .expect("should find voodoo output");

      let (commit_vout, commit_output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
        .expect("should find commit output");

      // reduce commit output to cover voodoo output
      let mut unsigned_commit_tx = unsigned_commit_tx.clone();
      unsigned_commit_tx.output[commit_vout].value = unsigned_commit_tx.output[commit_vout]
        .value
        .checked_sub(voodoo_output.value)
        .context("commit output value should be greater than voodoo output value")?;
      //.checked_sub(fee.to_sat())
      //.context("commit transaction output value insufficient to pay transaction fee")?;

      let (commit_vout, commit_output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
        .expect("should find commit output");

      //unsigned_commit_tx

      let (mut reveal_tx, fee) = Self::build_nocturnal_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint {
          txid: unsigned_commit_tx.txid(),
          vout: voodo_vout.try_into().unwrap(),
        },
        OutPoint {
          txid: unsigned_commit_tx.txid(),
          vout: commit_vout.try_into().unwrap(),
        },
        TxOut {
          script_pubkey: voodoo_change_address.script_pubkey(),
          value: voodoo_output.value,
        },
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: commit_output.value,
        },
        &reveal_script,
      );
      reveal_tx.output[0].value = 10_000;
      reveal_tx.output[1].value = 10_000;

      // endregion: --- vodoo spell

      let mut sighash_cache = SighashCache::new(&mut reveal_tx);
      let prevouts = [voodoo_output, commit_output];
      dbg!(prevouts);

      // let prevouts = [commit_output];
      let prevouts_all = Prevouts::All(&prevouts);

      let voodoo_signature_hash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts_all, SchnorrSighashType::Default)
        .expect("signature hash should compute");

      let commit_signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
          1,
          &prevouts_all,
          TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
          SchnorrSighashType::Default,
        )
        .expect("signature hash should compute");

      // potentail bug redo: message

      let signature =
        secp256k1.sign_schnorr(&voodoo_signature_hash.into(), &virgin_keypair.to_inner());

      let witness = sighash_cache
        .witness_mut(0)
        .expect("getting mutable witness reference should work");
      witness.push(signature.as_ref());

      let signature = secp256k1.sign_schnorr(&commit_signature_hash.into(), &key_pair);

      let witness = sighash_cache
        .witness_mut(1)
        .expect("getting mutable witness reference should work");
      witness.push(signature.as_ref());
      witness.push(reveal_script);
      witness.push(&control_block.serialize());

      (unsigned_commit_tx, reveal_tx)
    };

    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
      Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
        network,
      ),
      commit_tx_address
    );

    let reveal_weight = reveal_tx.weight();

    if !no_limit && reveal_weight > MAX_STANDARD_TX_WEIGHT.try_into().unwrap() {
      bail!(
        "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
      );
    }

    Ok((unsigned_commit_tx, reveal_tx, recovery_key_pair))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let recovery_private_key = PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network);

    let info = client.get_descriptor_info(&format!("rawtr({})", recovery_private_key.to_wif()))?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor: format!("rawtr({})#{}", recovery_private_key.to_wif(), info.checksum),
      timestamp: Timestamp::Now,
      active: Some(false),
      range: None,
      next_index: None,
      internal: Some(false),
      label: Some("commit tx recovery key".to_string()),
    })?;

    for result in response {
      if !result.success {
        return Err(anyhow!("commit tx recovery key import failed"));
      }
    }

    Ok(())
  }

  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: TxOut,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, fee)
  }

  fn build_nocturnal_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    voodoo: OutPoint,
    commit: OutPoint,
    voodoo_change: TxOut,
    genesis: TxOut,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![
        TxIn {
          previous_output: voodoo,
          script_sig: script::Builder::new().into_script(),
          witness: Witness::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        },
        TxIn {
          previous_output: commit,
          script_sig: script::Builder::new().into_script(),
          witness: Witness::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        },
      ],
      output: vec![voodoo_change, genesis],
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );

      reveal_tx.input[1].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[1].witness.push(script);
      reveal_tx.input[1].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, fee)
  }
}
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reveal_transaction_pays_fee() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      false,
    )
    .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((1.0 * (reveal_tx.vsize() as f64)).ceil() as u64);

    assert_eq!(
      reveal_tx.output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscript_tansactions_opt_in_to_rbf() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (commit_tx, reveal_tx, _) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      false,
    )
    .unwrap();

    assert!(commit_tx.is_explicitly_rbf());
    assert!(reveal_tx.is_explicitly_rbf());
  }

  #[test]
  fn inscribe_with_no_satpoint_and_no_cardinal_utxos() {
    let utxos = vec![(outpoint(1), Amount::from_sat(1000))];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      false,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains("wallet contains no cardinal utxos"),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_satpoint_and_enough_cardinal_utxos() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(20_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    assert!(Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      false,
    )
    .is_ok())
  }

  #[test]
  fn inscribe_with_custom_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let fee_rate = 3.3;

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      bitcoin::Network::Signet,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(fee_rate).unwrap(),
      FeeRate::try_from(fee_rate).unwrap(),
      false,
      false,
    )
    .unwrap();

    let sig_vbytes = 17;
    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(commit_tx.vsize() + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx.vsize())
      .to_sat();

    assert_eq!(
      reveal_tx.output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_with_commit_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let commit_fee_rate = 3.3;
    let fee_rate = 1.0;

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      bitcoin::Network::Signet,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(commit_fee_rate).unwrap(),
      FeeRate::try_from(fee_rate).unwrap(),
      false,
      false,
    )
    .unwrap();

    let sig_vbytes = 17;
    let fee = FeeRate::try_from(commit_fee_rate)
      .unwrap()
      .fee(commit_tx.vsize() + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx.vsize())
      .to_sat();

    assert_eq!(
      reveal_tx.output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_over_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      false,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains(&format!("reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): 402799")),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let (_commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      true,
      false,
    )
    .unwrap();

    assert!(reveal_tx.size() >= MAX_STANDARD_TX_WEIGHT as usize);
  }
}
