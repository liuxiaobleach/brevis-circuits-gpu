package main

import (
	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth162 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/influxdata/influxdb/pkg/deep"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.SingleNumSumCircuit{})
	if err != nil {
		log.Errorf("Receipt failed to compile for: %s\n", err.Error())
		return
	}

	log.Info("Start to setup pk")
	var pk = groth16.NewProvingKey(ecc.BN254)
	var vk = groth16.NewVerifyingKey(ecc.BN254)
	err1 := common.ReadProvingKey("test_single_number_circuit.pk", pk)
	err2 := common.ReadVerifyingKey("test_single_number_circuit.vk", vk)
	if err1 != nil || err2 != nil {
		log.Warnf("Failed to read pk and vk, and try create, %v, %v", err1, err2)
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			log.Fatalln(err)
		}
		common.WriteProvingKey(pk, "test_single_number_circuit.pk")
		common.WriteVerifyingKey(vk, "test_single_number_circuit.vk")

		var pkFromDisk = groth16.NewProvingKey(ecc.BN254)
		err1 := common.ReadProvingKey("test_single_number_circuit.pk", pkFromDisk)
		if err1 != nil {
			log.Fatalln(err1)
		}

		one := pk.(*groth162.ProvingKey)
		two := pkFromDisk.(*groth162.ProvingKey)

		CompareBN254ProvingKey(one, two)

	}

	log.Infoln("pk load done.")

	/*witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		log.Errorf("Receipt failed to setup for: %s\n", err.Error())
		return
	}*/

	// for bench
	/*var wg sync.WaitGroup
	log.Infoln("start prove")
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := 0; x < 100; x++ {
				_, err = groth16.Prove(ccs, pk, witness)
				if err != nil {
					log.Errorf("Receipt failed to prove for: %s\n", err.Error())
					return
				}
			}
		}()
	}
	wg.Wait()*/

	// for seq test
	/*for i := 0; i < 20; i++ {
		log.Infof("bench num: %d", i)
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			log.Errorf("Receipt failed to prove for: %s\n", err.Error())
			return
		}

		pubWitness, err := witness.Public()
		if err != nil {
			log.Errorf("Receipt failed to get pub witness for: %s\n", err.Error())
			return
		}

		err = groth16.Verify(proof, vk, pubWitness)
		if err != nil {
			log.Errorf("Receipt failed to get verify for: %s\n", err.Error())
			return
		}
	}*/

	log.Infoln("finish prove")
}

func CompareBN254ProvingKey(one, two *groth162.ProvingKey) {
	log.Infof("one.IsDifferent(two): %v", one.IsDifferent(two))

	log.Infof("deep.Equal(one.Domain, two.Domain): %v", deep.Equal(one.Domain, two.Domain))
	log.Infof("deep.Equal(one.G1, two.G1): %v", deep.Equal(one.G1, two.G1))
	log.Infof("deep.Equal(one.G1InfPointIndices, two.G1InfPointIndices): %v", deep.Equal(one.G1InfPointIndices, two.G1InfPointIndices))

	log.Infof("one.G1InfPointIndices: %+v", one.G1InfPointIndices)
	log.Infof("two.G1InfPointIndices: %+v", two.G1InfPointIndices)

	log.Infof("deep.Equal(one.G2, two.G2): %v", deep.Equal(one.G2, two.G2))
	log.Infof("deep.Equal(one.InfinityA, two.InfinityA): %v", deep.Equal(one.InfinityA, two.InfinityA))
	log.Infof("deep.Equal(one.InfinityB, two.InfinityB): %v", deep.Equal(one.InfinityB, two.InfinityB))
	log.Infof("deep.Equal(one.G1, two.G1): %v", deep.Equal(one.NbInfinityA, two.NbInfinityA))
	log.Infof("deep.Equal(one.G1, two.G1): %v", deep.Equal(one.NbInfinityB, two.NbInfinityB))
	log.Infof("deep.Equal(one.G1, two.G1): %v", deep.Equal(one.CommitmentKey, two.CommitmentKey))
}
