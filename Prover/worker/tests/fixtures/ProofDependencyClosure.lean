namespace AutoLean.ProofDependencyFixture

universe u

theorem allowedHelper (antecedent consequent : Prop)
    (combined : antecedent ∧ (antecedent → consequent)) : consequent :=
  combined.2 combined.1

theorem nonalias (antecedent consequent : Prop) (proof : antecedent)
    (implication : antecedent → consequent) : consequent :=
  allowedHelper antecedent consequent ⟨proof, implication⟩

theorem exactTypeAlias (antecedent consequent : Prop) (proof : antecedent)
    (implication : antecedent → consequent) : consequent :=
  nonalias antecedent consequent proof implication

theorem forbiddenStrong (proposition : Prop) (proof : proposition) : proposition :=
  proof

theorem allowedWrapper (proposition : Prop) (proof : proposition) : proposition :=
  forbiddenStrong proposition proof

theorem disguised (proposition : Prop) (proof : proposition) : proposition :=
  allowedWrapper proposition proof

theorem quotientProbe :
    ∀ {α : Sort u} {relation : α → α → Prop} {motive : Quot relation → Prop},
      (∀ value, motive (Quot.mk relation value)) →
        ∀ quotient, motive quotient :=
  @Quot.ind

end AutoLean.ProofDependencyFixture
