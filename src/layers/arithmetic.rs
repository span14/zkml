use std::{collections::HashMap, rc::Rc};

use halo2_proofs::{
  circuit::{AssignedCell, Layouter},
  halo2curves::FieldExt,
  plonk::Error,
};
use ndarray::{Array, IxDyn};

use crate::{gadgets::gadget::GadgetConfig, utils::helpers::broadcast};

pub mod add;
pub mod mul;

pub trait Arithmetic<F: FieldExt> {
  fn gadget_forward(
    &self,
    layouter: impl Layouter<F>,
    vec_inputs: &Vec<Vec<&AssignedCell<F, F>>>,
    constants: &Vec<AssignedCell<F, F>>,
    gadget_config: Rc<GadgetConfig>,
  ) -> Result<Vec<AssignedCell<F, F>>, Error>;

  fn arithmetic_forward(
    &self,
    mut layouter: impl Layouter<F>,
    tensors: &Vec<Array<AssignedCell<F, F>, IxDyn>>,
    constants: &HashMap<i64, AssignedCell<F, F>>,
    gadget_config: Rc<GadgetConfig>,
  ) -> Result<(Vec<AssignedCell<F, F>>, Vec<usize>), Error> {
    assert_eq!(tensors.len(), 2);
    println!("tensors: {:?} {:?}", tensors[0].shape(), tensors[1].shape());
    let (inp1, inp2) = broadcast(&tensors[0], &tensors[1]);
    let out_shape = inp1.shape().clone();
    assert_eq!(inp1.shape(), inp2.shape());

    let zero = constants.get(&0).unwrap().clone();

    let inp1_vec = inp1.iter().collect::<Vec<_>>();
    let inp2_vec = inp2.iter().collect::<Vec<_>>();
    let vec_inputs = vec![inp1_vec, inp2_vec];
    let constants = vec![zero.clone()];
    let out = self.gadget_forward(
      layouter.namespace(|| ""),
      &vec_inputs,
      &constants,
      gadget_config.clone(),
    )?;
    Ok((out, out_shape.to_vec()))
  }
}