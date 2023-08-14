package core

import "github.com/consensys/gnark/frontend"

type SmallProofCircuit struct {
	In  frontend.Variable `gnark:",public"`
	Out frontend.Variable
}

func (c *SmallProofCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.In, c.Out)
	return nil
}
