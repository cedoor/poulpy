//! Reproducer for the `FheUint::encrypt_sk -> FheUintPrepared::prepare -> add`
//! correctness regression.
//!
//! `test_bdd_add` (see `add.rs`) encrypts directly into `FheUintPrepared` via
//! `FheUintPreparedEncryptSk` and exercises only `add`. The path validated by
//! the example in `poulpy-schemes/examples/bdd_arithmetic.rs` — encrypt with
//! `FheUint::encrypt_sk`, then prepare with `FheUintPrepared::prepare`, then
//! `add` — is not asserted end-to-end anywhere in the existing test suite
//! (`test_bdd_prepare` exercises only the `FheUintPreparedDebug` standard-form
//! variant and only checks noise bounds). With identical layouts and scratch
//! sizing as `test_bdd_add`, this test fails: the decrypted result is garbage.

use poulpy_core::{
    EncryptionLayout, GGSWNoise, GLWEDecrypt, GLWEEncryptSk, GLWENoise, ScratchTakeCore,
    layouts::{GGSWLayout, GLWELayout, GLWESecretPrepared, GLWESecretPreparedFactory},
};
use poulpy_hal::{
    api::{ModuleNew, ScratchOwnedAlloc, ScratchOwnedBorrow},
    layouts::{Backend, DeviceBuf, Module, Scratch, ScratchOwned},
    source::Source,
};
use rand::Rng;

use crate::bin_fhe::{
    bdd_arithmetic::{
        Add, BDDKeyEncryptSk, BDDKeyPrepared, BDDKeyPreparedFactory, ExecuteBDDCircuit2WTo1W, FheUint, FheUintPrepare,
        FheUintPrepareDebug, FheUintPrepared, FheUintPreparedEncryptSk, FheUintPreparedFactory,
        tests::test_suite::{TEST_GGSW_INFOS, TEST_GLWE_INFOS, TestContext},
    },
    blind_rotation::BlindRotationAlgo,
};

pub fn test_bdd_prepare_then_add<BRA: BlindRotationAlgo, BE: Backend>(test_context: &TestContext<BRA, BE>)
where
    Module<BE>: ModuleNew<BE>
        + GLWESecretPreparedFactory<BE>
        + GLWEDecrypt<BE>
        + GLWENoise<BE>
        + FheUintPreparedFactory<u32, BE>
        + FheUintPreparedEncryptSk<u32, BE>
        + FheUintPrepareDebug<BRA, u32, BE>
        + BDDKeyEncryptSk<BRA, BE>
        + BDDKeyPreparedFactory<BRA, BE>
        + GGSWNoise<BE>
        + FheUintPrepare<BRA, BE>
        + ExecuteBDDCircuit2WTo1W<BE>
        + GLWEEncryptSk<BE>,
    ScratchOwned<BE>: ScratchOwnedAlloc<BE> + ScratchOwnedBorrow<BE>,
    Scratch<BE>: ScratchTakeCore<BE>,
{
    let glwe_infos: GLWELayout = TEST_GLWE_INFOS;
    let ggsw_infos: GGSWLayout = TEST_GGSW_INFOS;

    let module: &Module<BE> = &test_context.module;
    let sk_glwe_prep: &GLWESecretPrepared<DeviceBuf<BE>, BE> = &test_context.sk_glwe;
    let bdd_key_prepared: &BDDKeyPrepared<DeviceBuf<BE>, BRA, BE> = &test_context.bdd_key;

    let mut source: Source = Source::new([6u8; 32]);
    let mut source_xa: Source = Source::new([2u8; 32]);
    let mut source_xe: Source = Source::new([3u8; 32]);

    let mut scratch: ScratchOwned<BE> = ScratchOwned::alloc(1 << 22);

    // Encrypt as packed GLWE (same path as the bdd_arithmetic example).
    let glwe_enc_infos = EncryptionLayout::new_from_default_sigma(glwe_infos).unwrap();
    let mut a_enc: FheUint<Vec<u8>, u32> = FheUint::alloc_from_infos(&glwe_infos);
    let mut b_enc: FheUint<Vec<u8>, u32> = FheUint::alloc_from_infos(&glwe_infos);
    let a: u32 = source.next_u32();
    let b: u32 = source.next_u32();

    a_enc.encrypt_sk(
        module,
        a,
        sk_glwe_prep,
        &glwe_enc_infos,
        &mut source_xe,
        &mut source_xa,
        scratch.borrow(),
    );
    b_enc.encrypt_sk(
        module,
        b,
        sk_glwe_prep,
        &glwe_enc_infos,
        &mut source_xe,
        &mut source_xa,
        scratch.borrow(),
    );

    // Sanity: packed encryptions decrypt to plaintext on their own.
    assert_eq!(a_enc.decrypt(module, sk_glwe_prep, scratch.borrow()), a);
    assert_eq!(b_enc.decrypt(module, sk_glwe_prep, scratch.borrow()), b);

    // Prepare via the production `FheUintPrepared::prepare` path (the one used
    // by the example, not `FheUintPreparedDebug`).
    let mut a_enc_prep: FheUintPrepared<DeviceBuf<BE>, u32, BE> =
        FheUintPrepared::<DeviceBuf<BE>, u32, BE>::alloc_from_infos(module, &ggsw_infos);
    let mut b_enc_prep: FheUintPrepared<DeviceBuf<BE>, u32, BE> =
        FheUintPrepared::<DeviceBuf<BE>, u32, BE>::alloc_from_infos(module, &ggsw_infos);

    let prep_bytes: usize = module.fhe_uint_prepare_tmp_bytes(
        TEST_GGSW_INFOS.dnum.0 as usize,
        1,
        &a_enc_prep,
        &a_enc,
        bdd_key_prepared,
    );
    let mut scratch_prep: ScratchOwned<BE> = ScratchOwned::alloc(prep_bytes.max(1 << 22));
    a_enc_prep.prepare(module, &a_enc, bdd_key_prepared, scratch_prep.borrow());
    b_enc_prep.prepare(module, &b_enc, bdd_key_prepared, scratch_prep.borrow());

    // Same `add` invocation as `test_bdd_add` (single-thread variant).
    let mut res: FheUint<Vec<u8>, u32> = FheUint::<Vec<u8>, u32>::alloc_from_infos(&glwe_infos);
    let add_bytes: usize = res.add_tmp_bytes(module, &glwe_infos, &ggsw_infos, bdd_key_prepared);
    let mut scratch_add: ScratchOwned<BE> = ScratchOwned::alloc(add_bytes);
    res.add(module, &a_enc_prep, &b_enc_prep, bdd_key_prepared, scratch_add.borrow());

    assert_eq!(
        res.decrypt(module, sk_glwe_prep, scratch.borrow()),
        a.wrapping_add(b),
        "prepare-from-FheUint -> add path produced incorrect plaintext (a={a}, b={b})",
    );
}
