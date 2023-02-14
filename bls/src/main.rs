use std::cell::RefCell;
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
use halo2_proofs::pairing::group::Group;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, create_proof, Error, keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use halo2ecc_s::assign::{AssignedCondition, AssignedG2Affine};
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::ecc_chip::EccChipBaseOps;
use halo2ecc_s::circuit::fq12::{Fq12ChipOps, Fq2ChipOps};
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;

#[derive(Clone)]
struct TestChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
}

#[derive(Default, Clone)]
struct TestCircuit<N: FieldExt> {
    records: Records<N>,
}


impl<N: FieldExt> Circuit<N> for TestCircuit<N> {
    type Config = TestChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<N>::configure(meta);
        TestChipConfig {
            base_chip_config,
            range_chip_config,
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
    println!("Hello, bls!");

    let ctx = Rc::new(RefCell::new(Context::new()));
    let mut ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(ctx);

    let a = G1::random(&mut OsRng);

    let b = G2Affine::from(G2::random(&mut OsRng));
    let c = halo2_proofs::pairing::bls12_381::Fr::random(&mut OsRng);
    let ac = a * c;
    let bc = G2Affine::from(b * c);



    let bx = ctx.fq2_assign_constant((b.x.c0, b.x.c1));
    let by = ctx.fq2_assign_constant((b.y.c0, b.y.c1));
    let b = AssignedG2Affine::new(
        bx,
        by,
        AssignedCondition(ctx.native_ctx.borrow_mut().assign_constant(Fr::zero())),
    );

    let bcx = ctx.fq2_assign_constant((bc.x.c0, bc.x.c1));
    let bcy = ctx.fq2_assign_constant((bc.y.c0, bc.y.c1));
    let bc = AssignedG2Affine::new(
        bcx,
        bcy,
        AssignedCondition(ctx.native_ctx.borrow_mut().assign_constant(Fr::zero())),
    );

    let neg_a = ctx.assign_point(&-a);
    let ac = ctx.assign_point(&ac);

    ctx.check_pairing(&[(&ac, &b), (&neg_a, &bc)]);

    let in_ctx: Context<Fr> = ctx.into();

    println!("offset {} {}", in_ctx.range_offset, in_ctx.base_offset);

    let circuit = TestCircuit::<Fr> {
        records: Arc::try_unwrap(in_ctx.records).unwrap().into_inner().unwrap(),
    };

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
