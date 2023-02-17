extern crate core;

use std::cell::RefCell;
use std::ops::Neg;
use std::rc::Rc;
use std::sync::Arc;
use ark_std::{end_timer, start_timer};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::bls12_381::{G1, G1Affine, G2, G2Affine};
use halo2_proofs::pairing::bn256::{Bn256, Fr};
use halo2ecc_s::circuit::base_chip::{BaseChip, BaseChipConfig};
use halo2ecc_s::circuit::range_chip::{RangeChip, RangeChipConfig};
use halo2ecc_s::context::{Context, GeneralScalarEccContext, Records};
use rand::rngs::OsRng;
use halo2_proofs::pairing::group::{Curve, Group};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, create_proof, Error, keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use halo2ecc_s::assign::{AssignedCondition, AssignedG2Affine, AssignedInteger, AssignedValue};
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::ecc_chip::EccChipBaseOps;
use halo2ecc_s::circuit::fq12::{Fq12ChipOps, Fq2ChipOps};
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use poseidonhash::hash::{PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};

#[derive(Clone)]
struct TestChipConfig<N: FieldExt> {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    poseidon_chip_config: (PoseidonHashConfig<N>, usize),
}

#[derive(Default, Clone)]
struct TestCircuit<N: FieldExt> {
    records: Records<N>,
    pub_key_x_assigned_vals: Vec<N>,
}

const TEST_STEP: usize = 32;
const POSEIDON_MAX_ROW: usize =4;

impl<N: FieldExt + poseidonhash::Hashable> Circuit<N> for TestCircuit<N> {
    type Config = TestChipConfig<N>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<N>::configure(meta);
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        let poseidon_chip_config = (
            PoseidonHashConfig::configure_sub(meta, hash_tbl, TEST_STEP),
            POSEIDON_MAX_ROW,
        );
        TestChipConfig {
            base_chip_config,
            range_chip_config,
            poseidon_chip_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_chip = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<N>::new(config.range_chip_config);
        range_chip.init_table(&mut layouter)?;

        let poseidon_inputs = self.pub_key_x_assigned_vals.chunks(2).map(|w| [w[0], w[1]]).collect::<Vec<_>>();

        let poseidon_hash_table = PoseidonHashTable {
            inputs: poseidon_inputs,
            inputs_recursion: [N::from(3); 100].to_vec(),
            ..Default::default()
        };
        let poseidon_chip = PoseidonHashChip::<N, TEST_STEP>::construct(
            config.poseidon_chip_config.0,
            &poseidon_hash_table,
            POSEIDON_MAX_ROW,
            false,
            Some(N::from(42u64)),
        );
        poseidon_chip.load(&mut layouter).unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let timer = start_timer!(|| "assign");
                self.records
                    .assign_all(&mut region, &base_chip, &range_chip)?;
                end_timer!(timer);
                Ok(())
            },
        )?;

        Ok(())
    }
}

fn main() {
    println!("process pos snark 2!");

    let ctx = Rc::new(RefCell::new(Context::new()));
    let mut ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(ctx);

    // prepare g1, sig, pubkey, signMsg
    let prv_key_scalar_1 = halo2_proofs::pairing::bls12_381::Fr::random(&mut OsRng);
    let prv_key_scalar_2 = halo2_proofs::pairing::bls12_381::Fr::random(&mut OsRng);

    let pub_key_1 = G1::generator() * prv_key_scalar_1;
    let pub_key_2 = G1::generator() * prv_key_scalar_2;

    let sign_msg = G2Affine::from(G2::random(&mut OsRng));
    let sig = G2Affine::from(sign_msg * (prv_key_scalar_1 + prv_key_scalar_2));

    // assign pub keys.
    let assigned_pub_key_1 = ctx.assign_point(&pub_key_1);
    let assigned_pub_key_2 = ctx.assign_point(&pub_key_2);

    let mut pub_key_x_assigned_vals: Vec<Fr> = Vec::new();
    let mut pub_key_1_limbs = assigned_pub_key_1.x.limbs_le.iter().map(|w| w.val).collect::<Vec<_>>();
    let mut pub_key_2_limbs = assigned_pub_key_2.x.limbs_le.iter().map(|w| w.val).collect::<Vec<_>>();;
    pub_key_x_assigned_vals.append(&mut pub_key_1_limbs);
    pub_key_x_assigned_vals.append(&mut pub_key_2_limbs);

    // agg pub keys.
    // TODO add recursive.
    let assigned_pub_key_1_with_cvr = ctx.to_point_with_curvature(assigned_pub_key_1);
    let assigned_pub_key_agg = ctx.ecc_add(&assigned_pub_key_1_with_cvr, &assigned_pub_key_2);

    // assign G1 generator
    let g1_generate = G1::generator();
    let assigned_g1_generate = ctx.assign_point(&g1_generate);
    let assigned_g1_generate_neg = ctx.assign_point(&g1_generate.neg());

    // assign sig
    let sig_x = ctx.fq2_assign_constant((sig.x.c0, sig.x.c1));
    let sig_y = ctx.fq2_assign_constant((sig.y.c0, sig.y.c1));
    let assigned_sig: AssignedG2Affine<G1Affine, Fr> = AssignedG2Affine::new(
        sig_x,
        sig_y,
        AssignedCondition(ctx.native_ctx.borrow_mut().assign_constant(Fr::zero())),
    );
    // assign sign msg
    let sign_msg_x = ctx.fq2_assign_constant((sign_msg.x.c0, sign_msg.x.c1));
    let sign_msg_y = ctx.fq2_assign_constant((sign_msg.y.c0, sign_msg.y.c1));
    let assigned_sign_msg: AssignedG2Affine<G1Affine, Fr> = AssignedG2Affine::new(
        sign_msg_x,
        sign_msg_y,
        AssignedCondition(ctx.native_ctx.borrow_mut().assign_constant(Fr::zero())),
    );

    ctx.check_pairing(&[(&assigned_g1_generate_neg, &assigned_sig), (&assigned_pub_key_agg, &assigned_sign_msg)]);

    let in_ctx: Context<Fr> = ctx.into();

    println!("offset {} {}", in_ctx.range_offset, in_ctx.base_offset);

    let circuit = TestCircuit::<Fr> {
        records: Arc::try_unwrap(in_ctx.records).unwrap().into_inner().unwrap(),
        pub_key_x_assigned_vals,
    };

    /*let k = 22;
    let timer_mock_prover = start_timer!(|| "mock_prover");
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    end_timer!(timer_mock_prover);*/
    //assert_eq!(prover.verify(), Ok(()));

    let k = 22;

    let timer = start_timer!(|| format!("build params with K = {}", k));
    let params: Params<halo2_proofs::pairing::bn256::G1Affine> = Params::<halo2_proofs::pairing::bn256::G1Affine>::unsafe_setup::<Bn256>(k);
    end_timer!(timer);

    let timer = start_timer!(|| "build vk");
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    end_timer!(timer);

    let vk_for_verify = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

    let timer = start_timer!(|| "build pk");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    end_timer!(timer);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let timer = start_timer!(|| "create proof");
    create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("proof generation should not fail");
    end_timer!(timer);

    let proof = transcript.finalize();

    println!("proof size: {}", proof.len());

    /*let params_verifier: ParamsVerifier<Bn256> = params.verifier(0).unwrap();

    let strategy = SingleVerifier::new(&params_verifier);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let timer = start_timer!(|| "verify proof");
    verify_proof(
        &params_verifier,
        &vk_for_verify,
        strategy,
        &[&[]],
        &mut transcript,
    )
        .unwrap();
    end_timer!(timer);*/
}
