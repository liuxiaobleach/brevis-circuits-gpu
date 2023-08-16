package main

import (
	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/util"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"reflect"
)

func main() {
	contractAddr := "0x87c644c9b0bd2c14f0952aed75e242237e7e3510"
	topic := "0x7ae1420774474a63c6da37d66e70351e80273a7f6a538d8c05d21d727571dded"
	fromAddr := "0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1"
	txHash := "0x78a175f07d49f3d57e35ec40eca2b7e160dc9cf04fa8103812ede1ca128e7149"
	smtRoot := "0x0000000000000000000000000000000000000000000000000000000000000001"
	vol := uint64(14)
	rpc := "https://goerli.blockpi.network/v1/rpc/public"

	assignment, _, err := util.GenerateReceiptSingleNumSumCircuitProofWitness(rpc, smtRoot, txHash, contractAddr, fromAddr, topic, vol)
	if err != nil {
		log.Fatalln(err)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.SingleNumSumCircuit{})
	if err != nil {
		log.Errorf("Receipt failed to compile for: %s\n", err.Error())
		return
	}

	log.Info("Start to setup pk")
	var pk = groth16.NewProvingKey(ecc.BN254)
	var diskPk = groth16.NewProvingKey(ecc.BN254)
	var vk = groth16.NewVerifyingKey(ecc.BN254)
	err1 := common.ReadProvingKey("test_single_number_circuit.pk", diskPk)
	err2 := common.ReadVerifyingKey("test_single_number_circuit.vk", vk)
	if err1 != nil || err2 != nil {
		log.Warnf("Failed to read pk and vk, and try create, %v, %v", err1, err2)
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			log.Fatalln(err)
		}
		common.WriteProvingKey(pk, "test_single_number_circuit.pk")
		common.WriteVerifyingKey(vk, "test_single_number_circuit.vk")

		// first time create pk vk. let's compare pk
		err = common.ReadProvingKey("test_single_number_circuit.pk", diskPk)
		if err != nil {
			log.Fatalln(err)
		}
		CompareBn254Pk(pk.(*groth16_bn254.ProvingKey), diskPk.(*groth16_bn254.ProvingKey))
	}

	log.Infoln("pk load done.")

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		log.Errorf("Receipt failed to setup for: %s\n", err.Error())
		return
	}

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
	for i := 0; i < 20; i++ {
		log.Infof("bench num: %d", i)
		proof, err := groth16.Prove(ccs, diskPk, witness)
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
	}

	log.Infoln("finish prove")
}

func CompareBn254Pk(pk, origPk *groth16_bn254.ProvingKey) {
	log.Infof("pk == pk_from_disk G1 %v", reflect.DeepEqual(pk.G1, origPk.G1))
	log.Infof("pk == pk_from_disk G1.A %v", reflect.DeepEqual(pk.G1.A, origPk.G1.A))
	log.Infof("pk == pk_from_disk G1.B %v", reflect.DeepEqual(pk.G1.B, origPk.G1.B))
	log.Infof("pk == pk_from_disk G1.Z %v", reflect.DeepEqual(pk.G1.Z, origPk.G1.Z))
	log.Infof("pk == pk_from_disk G1.K %v", reflect.DeepEqual(pk.G1.K, origPk.G1.K))
	log.Infof("pk == pk_from_disk G1.Alpha %v", reflect.DeepEqual(pk.G1.Alpha, origPk.G1.Alpha))
	log.Infof("pk == pk_from_disk G1.Beta %v", reflect.DeepEqual(pk.G1.Beta, origPk.G1.Beta))
	log.Infof("pk == pk_from_disk G1.Delta %v", reflect.DeepEqual(pk.G1.Delta, origPk.G1.Delta))

	log.Infof("pk == pk_from_disk G1Device %v", reflect.DeepEqual(pk.G1Device, origPk.G1Device))

	log.Infof("pk == pk_from_disk G2 %v", reflect.DeepEqual(pk.G2, origPk.G2))
	log.Infof("pk == pk_from_disk G1Device %v", reflect.DeepEqual(pk.G2Device, origPk.G2Device))

	log.Infof("pk == pk_from_disk Domain %v", reflect.DeepEqual(pk.Domain, origPk.Domain))
	log.Infof("pk == pk_from_disk DomainDevice %v", reflect.DeepEqual(pk.DomainDevice, origPk.DomainDevice))
	log.Infof("pk == pk_from_disk DenDevice %v", reflect.DeepEqual(pk.DenDevice, origPk.DenDevice))

	log.Infof("pk == pk_from_disk InfinityA %v", reflect.DeepEqual(pk.InfinityA, origPk.InfinityA))
	log.Infof("pk == pk_from_disk InfinityB %v", reflect.DeepEqual(pk.InfinityB, origPk.InfinityB))

	log.Infof("pk == pk_from_disk NbInfinityA %v", reflect.DeepEqual(pk.NbInfinityA, origPk.NbInfinityA))
	log.Infof("pk == pk_from_disk NbInfinityB %v", reflect.DeepEqual(pk.NbInfinityB, origPk.NbInfinityB))
	log.Infof("pk == pk_from_disk CommitmentKey %v", reflect.DeepEqual(pk.CommitmentKey, origPk.CommitmentKey))

	log.Infof("pk == pk_from_disk all %v", reflect.DeepEqual(pk, origPk))
}
