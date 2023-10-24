package main

import (
	"fmt"
	"github.com/celer-network/brevis-circuits/index-proof/core"
	"github.com/celer-network/brevis-circuits/index-proof/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/rlp"
	"log"
	"os"
	"runtime/debug"
)

func main() {
	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.IndexCheckCircuit{})
	if err != nil {
		log.Fatal("frontend.Compile")
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("groth16.Setup")
	}

	var indexBuf []byte

	indexBuf = rlp.AppendUint64(indexBuf, uint64(1))
	input := utils.GetHexArray(fmt.Sprintf("%x", indexBuf), 6)
	if len(input) != 6 {
		log.Fatalf("invalid input, index: %d", 1)
	}
	var witnessInput [6]frontend.Variable
	for x, y := range input {
		witnessInput[x] = y
	}
	assignment := core.IndexCheckCircuit{
		Index:     1,
		RlpString: witnessInput,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}

	f, err := os.Create("BlkVerifier.sol")
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	err = vk.ExportSolidity(f)
}
