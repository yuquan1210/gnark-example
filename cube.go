package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X     frontend.Variable
	Sym_1 frontend.Variable
	Y     frontend.Variable
	Sym_2 frontend.Variable
	Out   frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	// x*x = sym_1
	api.AssertIsEqual(circuit.Sym_1, api.Mul(circuit.X, circuit.X))
	// sym_1 * x = y
	api.AssertIsEqual(circuit.Y, api.Mul(circuit.Sym_1, circuit.X))
	// y + x = sym_2
	api.AssertIsEqual(circuit.Sym_2, api.Mul(api.Add(circuit.Y, circuit.X), 1))
	// sym_2 + 5 = ~out
	api.AssertIsEqual(circuit.Out, api.Mul(api.Add(circuit.Sym_2, 5), 1))
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit CubicCircuit
	ccs, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	assignment := CubicCircuit{X: 3, Sym_1: 9, Y: 27, Sym_2: 30, Out: 35}
	witness, _ := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
