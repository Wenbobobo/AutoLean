import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude

/-!
# Offline freshness and capture controls

These countermodels are retained only for local semantic review of the source
split.  They are never part of an independent or compositional runtime
profile.  In particular, importing this module is a profile-boundary failure,
not a shortcut for a candidate proof.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

section RejectionControls

/-- The equality body `bound = free` exposes a reused eigenvariable. -/
def boundEqFree : Body Language.empty 1 :=
  BoundedFormula.equal
    (Term.var (Sum.inr 0))
    (Term.var (Sum.inl 0))

theorem reused_old_variable_premise_valid :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ValidIn Bool ([] : Side Language.empty 1)
      [inst0 boundEqFree (Term.var 0)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro assignment _
  left
  rw [inst0_realize]
  simp [boundEqFree, BoundedFormula.Realize]

theorem reused_old_variable_allRight_is_unsound :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬ValidIn Bool ([] : Side Language.empty 1) [boundEqFree.all] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro claimed
  have conclusion := claimed (fun _ => false) trivial
  rw [Side.anyRealize_cons] at conclusion
  rcases conclusion with conclusion | contradiction
  · have allValues := (all_realize boundEqFree (fun _ => false)).1 conclusion
    have := allValues true
    simp [boundEqFree, BoundedFormula.Realize] at this
  · exact contradiction.elim

def existsEqFree : Body Language.empty 2 :=
  BoundedFormula.equal
    (Term.var (Sum.inr 0))
    (Term.var (Sum.inl 0))

theorem reused_old_variable_existsLeft_premise_valid :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ValidIn Bool
      [inst0 existsEqFree (Term.var 1)]
      [inst0 existsEqFree (Term.var 1)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro _ antecedent
  exact Or.inl antecedent.1

theorem reused_old_variable_existsLeft_is_unsound :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬ValidIn Bool
      [existsEqFree.ex]
      [inst0 existsEqFree (Term.var 1)] := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro claimed
  let assignment : Fin 2 → Bool := ![false, true]
  have existential : Formula.Realize existsEqFree.ex assignment := by
    rw [Formula.Realize, BoundedFormula.realize_ex]
    refine ⟨false, ?_⟩
    simp [existsEqFree, assignment, BoundedFormula.Realize, Fin.snoc]
  have conclusion := claimed assignment ⟨existential, trivial⟩
  rcases conclusion with conclusion | contradiction
  · have opened :=
      (inst0_realize existsEqFree (Term.var 1) assignment).1 conclusion
    simp [existsEqFree, assignment, BoundedFormula.Realize] at opened
  · exact contradiction.elim

def captureBody : Body Language.empty 1 :=
  BoundedFormula.all <|
    BoundedFormula.equal
      (Term.var (Sum.inr (Fin.castSucc 0)))
      (Term.var (Sum.inr (Fin.last 1)))

def naivelyCaptured : Fml Language.empty 1 :=
  BoundedFormula.all <|
    BoundedFormula.equal
      (Term.var (Sum.inr 0))
      (Term.var (Sum.inr 0))

theorem naive_capture_would_be_true :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    Formula.Realize naivelyCaptured (fun _ => false) := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  simp [naivelyCaptured, Formula.Realize, BoundedFormula.Realize]

theorem inst0_capture_avoiding_control :
    letI : Language.empty.Structure Bool := Language.emptyStructure
    ¬Formula.Realize (inst0 captureBody (Term.var 0)) (fun _ => false) := by
  letI : Language.empty.Structure Bool := Language.emptyStructure
  intro captured
  have correctlyInstantiated :=
    (inst0_realize captureBody (Term.var 0) (fun _ => false)).1 captured
  have innerTrue := (BoundedFormula.realize_all.mp correctlyInstantiated) true
  simp [BoundedFormula.Realize, Fin.snoc] at innerTrue

end RejectionControls

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
