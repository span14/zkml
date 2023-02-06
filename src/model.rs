use std::{collections::HashMap, marker::PhantomData};

use halo2_proofs::{
  circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
  halo2curves::FieldExt,
  plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};
use ndarray::{Array, IxDyn};

use crate::{
  gadgets::{
    add_pairs::AddPairsChip, adder::AdderChip, bias_div_floor_relu6::BiasDivFloorRelu6Chip,
    dot_prod::DotProductChip, gadget::GadgetConfig,
  },
  layers::{
    dag::{DAGLayerChip, DAGLayerConfig},
    layer::{Layer, LayerConfig, LayerType},
  },
  utils::loader::{load_model_msgpack, ModelMsgpack},
};

#[derive(Clone, Debug)]
pub struct ModelCircuit<F: FieldExt> {
  pub dag_config: DAGLayerConfig,
  pub tensors: Vec<Array<Value<F>, IxDyn>>,
  pub _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct ModelConfig<F: FieldExt> {
  pub gadget_config: GadgetConfig,
  pub _marker: PhantomData<F>,
}

impl<F: FieldExt> ModelCircuit<F> {
  pub fn assign_tensors(
    &self,
    mut layouter: impl Layouter<F>,
    columns: &Vec<Column<Advice>>,
    tensors: &Vec<Array<Value<F>, IxDyn>>,
  ) -> Result<Vec<Array<AssignedCell<F, F>, IxDyn>>, Error> {
    let tensors = layouter.assign_region(
      || "asssignment",
      |mut region| {
        let mut assigned_tensors = Vec::new();
        let idx = 0;
        for tensor in tensors {
          let mut flat = vec![];
          for val in tensor.iter() {
            let row_idx = idx / columns.len();
            let col_idx = idx % columns.len();
            let cell = region.assign_advice(|| "assignment", columns[col_idx], row_idx, || *val)?;
            flat.push(cell);
          }
          let tensor = Array::from_shape_vec(tensor.shape(), flat).unwrap();
          assigned_tensors.push(tensor);
        }
        Ok(assigned_tensors)
      },
    )?;

    Ok(tensors)
  }

  // FIXME: assign to public
  pub fn assign_constants(
    &self,
    mut layouter: impl Layouter<F>,
    model_config: &ModelConfig<F>,
  ) -> Result<HashMap<i64, AssignedCell<F, F>>, Error> {
    let columns = model_config.gadget_config.columns.clone();
    let sf = model_config.gadget_config.scale_factor;

    let constants = layouter.assign_region(
      || "constants",
      |mut region| {
        let mut constants: HashMap<i64, AssignedCell<F, F>> = HashMap::new();
        let zero = region.assign_advice(|| "zero", columns[0], 0, || Value::known(F::zero()))?;
        let one = region.assign_advice(|| "one", columns[0], 1, || Value::known(F::one()))?;
        // FIXME
        let sf = region.assign_advice(|| "sf", columns[0], 2, || Value::known(F::from(sf)))?;

        constants.insert(0, zero);
        constants.insert(1, one);
        constants.insert(2, sf);
        Ok(constants)
      },
    )?;
    Ok(constants)
  }

  pub fn generate_from_file(config_file: &str) -> ModelCircuit<F> {
    let config: ModelMsgpack = load_model_msgpack(config_file);

    let to_value = |x: i64| {
      let bias = 1 << 31;
      let x_pos = x + bias;
      Value::known(F::from(x_pos as u64)) - Value::known(F::from(bias as u64))
    };

    let match_layer = |x: &str| match x {
      "Conv2D" => LayerType::Conv2D,
      _ => panic!("unknown op"),
    };

    let mut tensors = vec![];
    for flat in config.tensors {
      let value_flat = flat.data.iter().map(|x| to_value(*x)).collect::<Vec<_>>();
      let shape = flat.shape.iter().map(|x| *x as usize).collect::<Vec<_>>();
      let tensor = Array::from_shape_vec(IxDyn(&shape), value_flat).unwrap();
      tensors.push(tensor);
    }

    let dag_config = {
      let ops = config
        .layers
        .iter()
        .map(|layer| LayerConfig {
          layer_type: match_layer(&layer.layer_type),
          layer_params: layer.params.clone(),
        })
        .collect::<Vec<_>>();
      let inp_idxes = config
        .layers
        .iter()
        .map(|layer| {
          layer
            .inp_idxes
            .iter()
            .map(|x| *x as usize)
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
      let out_idxes = config
        .layers
        .iter()
        .map(|layer| {
          layer
            .out_idxes
            .iter()
            .map(|x| *x as usize)
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
      let final_out_idxes = config
        .out_idxes
        .iter()
        .map(|x| *x as usize)
        .collect::<Vec<_>>();
      DAGLayerConfig {
        inp_idxes,
        out_idxes,
        ops,
        final_out_idxes,
      }
    };

    ModelCircuit {
      tensors,
      _marker: PhantomData,
      dag_config,
    }
  }
}

impl<F: FieldExt> Circuit<F> for ModelCircuit<F> {
  type Config = ModelConfig<F>;
  type FloorPlanner = SimpleFloorPlanner;

  fn without_witnesses(&self) -> Self {
    todo!()
  }

  fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
    // FIXME: decide which gadgets to make
    let mut gadget_config = GadgetConfig::default();
    gadget_config = AddPairsChip::<F>::configure(meta, gadget_config);
    gadget_config = AdderChip::<F>::configure(meta, gadget_config);
    gadget_config = BiasDivFloorRelu6Chip::<F>::configure(meta, gadget_config);
    gadget_config = DotProductChip::<F>::configure(meta, gadget_config);

    ModelConfig {
      gadget_config,
      _marker: PhantomData,
    }
  }

  fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
    let tensors = self.assign_tensors(
      layouter.namespace(|| "assignment"),
      &config.gadget_config.columns,
      &self.tensors,
    )?;
    let constants = self.assign_constants(layouter.namespace(|| "constants"), &config)?;

    let dag_chip = DAGLayerChip::<F>::construct(self.dag_config.clone());
    let _result = dag_chip.forward(
      layouter.namespace(|| "dag"),
      &tensors,
      &constants,
      &config.gadget_config,
    )?;

    Ok(())
  }
}