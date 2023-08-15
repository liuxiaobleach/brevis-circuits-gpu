package main

import (
	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/small/core"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.SmallProofCircuit{})
	if err != nil {
		log.Errorf("Receipt failed to compile for: %s\n", err.Error())
		return
	}

	log.Info("Start to setup pk")
	var pk = groth16.NewProvingKey(ecc.BN254)
	err = common.ReadProvingKey("test_small_circuit.pk", pk)
	if err != nil {
		log.Warnf("Failed to read pk %s, and try create", err.Error())
		pk, _, err = groth16.Setup(ccs)
		if err != nil {
			log.Fatalln(err)
		}
		common.WriteProvingKey(pk, "test_small_circuit.pk")
	}
	log.Infoln("pk load done.")

	assignment := &core.SmallProofCircuit{
		In:  1,
		Out: 1,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		log.Errorf("Receipt failed to setup for: %s\n", err.Error())
		return
	}

	_, err = groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Errorf("Receipt failed to prove for: %s\n", err.Error())
		return
	}
}
