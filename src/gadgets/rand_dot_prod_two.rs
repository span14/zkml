use std::{marker::PhantomData, rc::Rc};

use halo2_proofs::{
  circuit::{AssignedCell, Layouter, Region, Value},
  halo2curves::ff::PrimeField,
  plonk::{Advice, Column, ConstraintSystem, Error, Expression},
  poly::Rotation,
};

use crate::gadgets::adder::AdderChip;

use super::gadget::{Gadget, GadgetConfig, GadgetType};

type RandDotProductTwoConfig = GadgetConfig;

pub struct RandDotProductTwoChip<F: PrimeField> {
  config: Rc<RandDotProductTwoConfig>,
  _marker: PhantomData<F>,
}

impl<F: PrimeField> RandDotProductTwoChip<F> {
  pub fn construct(config: Rc<RandDotProductTwoConfig>) -> Self {
    Self {
      config,
      _marker: PhantomData,
    }
  }

  pub fn get_input_columns(config: &GadgetConfig) -> Vec<Column<Advice>> {
    let num_inputs = config.columns.len() - 1;
    config.columns[0..num_inputs].to_vec()
  }

  pub fn get_weight_columns(_config: &GadgetConfig) -> Vec<Column<Advice>> {
    vec![]
  }

  pub fn configure(meta: &mut ConstraintSystem<F>, gadget_config: GadgetConfig) -> GadgetConfig {
    let selector = meta.selector();
    let columns = &gadget_config.columns;

    meta.create_gate("rand dot product two gate", |meta| {
      let s = meta.query_selector(selector);
      let gate_inp = RandDotProductTwoChip::<F>::get_input_columns(&gadget_config)
        .iter()
        .map(|col| meta.query_advice(*col, Rotation::cur()))
        .collect::<Vec<_>>();
    
      let gate_output = meta.query_advice(columns[columns.len() - 1], Rotation::cur());
      let c = &gadget_config.challenges[1].expr();

      let res = gate_inp
        .iter()
        .fold(
            (Expression::Constant(F::ZERO), c.clone()), 
            |a, b| {
                (a.0 + b.clone() * a.1.clone(), a.1 * c.clone())
            }
        );

      vec![s * (res.0 - gate_output)]
    });

    let mut selectors = gadget_config.selectors;
    selectors.insert(GadgetType::RandDotProductTwo, vec![selector]);

    GadgetConfig {
      columns: gadget_config.columns,
      selectors,
      ..gadget_config
    }
  }

  // The caller is expected to pad the inputs
  fn op_row_region_rand(
    &self,
    region: &mut Region<F>,
    row_offset: usize,
    vec_inputs: &Vec<Vec<(&AssignedCell<F, F>,F)>>,
    _single_inputs: &Vec<(&AssignedCell<F, F>, F)>,
    c: Value<F>,
  ) -> Result<Vec<(AssignedCell<F, F>, F)>, Error> {

    let inp = &vec_inputs[0];
    assert_eq!(inp.len(), self.num_inputs_per_row());

    let c_base = c.assign().map_or(F::from(0x123456789abcdef), |x| x);

    if self.config.use_selectors {
      let selector = self.config.selectors.get(&GadgetType::RandDotProductTwo).unwrap()[0];
      selector.enable(region, row_offset).unwrap();
    }

    let inp_cols = RandDotProductTwoChip::<F>::get_input_columns(&self.config);
    inp
      .iter()
      .enumerate()
      .map(|(i, cell)| cell.0.copy_advice(|| "", region, inp_cols[i], row_offset))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    

    let e = inp
      .iter()
      .fold((F::ZERO, c_base), |acc, x| {
        (acc.0 + x.1 * acc.1, acc.1 * c_base)
      });

    let res = region
      .assign_advice(
        || "",
        self.config.columns[self.config.columns.len() - 1],
        row_offset,
        || Value::known(e.0),
      )
      .unwrap();

    Ok(vec![(res, e.0)])
  }
}

impl<F: PrimeField> Gadget<F> for RandDotProductTwoChip<F> {
  fn name(&self) -> String {
    "rand dot product one".to_string()
  }

  fn num_cols_per_op(&self) -> usize {
    self.config.columns.len()
  }

  fn num_inputs_per_row(&self) -> usize {
    self.config.columns.len() - 1
  }

  fn num_outputs_per_row(&self) -> usize {
    1
  }

  // The caller is expected to pad the inputs
  fn op_row_region(
    &self,
    _region: &mut Region<F>,
    _row_offset: usize,
    _vec_inputs: &Vec<Vec<(&AssignedCell<F, F>,F)>>,
    _single_inputs: &Vec<(&AssignedCell<F, F>, F)>,
  ) -> Result<Vec<(AssignedCell<F, F>, F)>, Error> {
    unimplemented!()
  }

  fn forward(
    &self,
    mut layouter: impl Layouter<F>,
    vec_inputs: &Vec<Vec<(&AssignedCell<F, F>, F)>>,
    single_inputs: &Vec<(&AssignedCell<F, F>, F)>,
  ) -> Result<Vec<(AssignedCell<F, F>, F)>, Error> {
    // assert_eq!(vec_inputs.len(), 2);
    assert_eq!(single_inputs.len(), 1);
    let zero = &single_inputs[0];
    let c = layouter.get_challenge(self.config.challenges[1]);

    let mut inputs = vec_inputs[0].clone();
    while inputs.len() % self.num_inputs_per_row() != 0 {
      inputs.push(*zero);
    }

    let outputs = layouter
      .assign_region(
        || "rand dot product two rows",
        |mut region| {
          let mut outputs = vec![];
          for i in 0..inputs.len() / self.num_inputs_per_row() {
            let inp =
              inputs[i * self.num_inputs_per_row()..(i + 1) * self.num_inputs_per_row()].to_vec();
            let res = self
              .op_row_region_rand(&mut region, i, &vec![inp], &vec![zero.clone()], c)
              .unwrap();
            outputs.push(res[0].clone());
          }
          Ok(outputs)
        },
      )
      .unwrap();

    let adder_chip = AdderChip::<F>::construct(self.config.clone());
    let tmp = outputs.iter().map(|x| (&x.0, x.1)).collect::<Vec<_>>();
    Ok(
      adder_chip
        .forward(
          layouter.namespace(|| "rand dot product two adder"),
          &vec![tmp],
          single_inputs,
        )
        .unwrap(),
    )
  }
}
