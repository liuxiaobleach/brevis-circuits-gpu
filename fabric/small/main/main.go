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
	var vk = groth16.NewVerifyingKey(ecc.BN254)
	err1 := common.ReadProvingKey("test_small_circuit.pk", pk)
	err2 := common.ReadVerifyingKey("test_small_circuit.vk", vk)
	if err1 != nil || err2 != nil {
		log.Warnf("Failed to read pk and vk, and try create, err:%v %v", err1, err2)
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			log.Fatalln(err)
		}
		common.WriteProvingKey(pk, "test_small_circuit.pk")
		common.WriteVerifyingKey(vk, "test_small_circuit.vk")
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

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Errorf("Receipt failed to prove for: %s\n", err.Error())
		return
	}

	pubkWitness, err := witness.Public()
	if err != nil {
		log.Fatalln(err)
	}

	err = groth16.Verify(proof, vk, pubkWitness)
	if err != nil {
		log.Fatalln(err)
	}
}
