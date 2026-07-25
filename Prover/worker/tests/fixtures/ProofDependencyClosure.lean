namespace AutoLean.ProofDependencyFixture

theorem allowedHelper (proposition : Prop) (proof : proposition) : proposition :=
  proof

theorem forbiddenStrong (proposition : Prop) (proof : proposition) : proposition :=
  proof

theorem allowedWrapper (proposition : Prop) (proof : proposition) : proposition :=
  forbiddenStrong proposition proof

theorem independent (proposition : Prop) (proof : proposition) : proposition :=
  allowedHelper proposition proof

theorem disguised (proposition : Prop) (proof : proposition) : proposition :=
  allowedWrapper proposition proof

end AutoLean.ProofDependencyFixture
